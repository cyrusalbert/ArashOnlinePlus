// Package xray builds multi-outbound Xray configs and manages the xray-core process.
//
// One Xray process hosts a whole batch of configs: every config gets its own local SOCKS
// inbound and a routing rule that sends that inbound to that config's outbound, so a batch
// can be tested in parallel through "127.0.0.1:<port>".
package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"arashonline/internal/model"
)

// Version returns the first line printed by "xray version".
func Version(bin string) (string, error) {
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, lastLine(string(out)))
	}
	lines := nonEmptyLines(string(out))
	if len(lines) == 0 {
		return "", errors.New("no output from xray version")
	}
	return lines[0], nil
}

// TestConfig asks Xray to validate a config ("xray run -test") without starting it.
func TestConfig(bin string, nodes []*model.Node) error {
	cfg, err := BuildConfig(nodes, []int{10808}, "none")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "xray-test-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(cfg); err != nil {
		f.Close()
		return err
	}
	f.Close()
	out, err := exec.Command(bin, "run", "-test", "-config", f.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, lastLine(string(out)))
	}
	return nil
}

// BuildConfig renders one Xray config: nodes[i] is reachable via SOCKS 127.0.0.1:ports[i].
func BuildConfig(nodes []*model.Node, ports []int, logLevel string) ([]byte, error) {
	if len(nodes) != len(ports) {
		return nil, errors.New("nodes/ports length mismatch")
	}
	inbounds := make([]any, 0, len(nodes))
	outbounds := make([]any, 0, len(nodes)+1)
	rules := make([]any, 0, len(nodes))

	// First outbound is the default: anything not matched by a rule is dropped.
	outbounds = append(outbounds, map[string]any{"tag": "block", "protocol": "blackhole"})

	for i, n := range nodes {
		inTag := fmt.Sprintf("in-%d", i)
		outTag := fmt.Sprintf("out-%d", i)
		inbounds = append(inbounds, map[string]any{
			"tag":      inTag,
			"listen":   "127.0.0.1",
			"port":     ports[i],
			"protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		})
		ob := make(map[string]any, len(n.Outbound)+1)
		for k, v := range n.Outbound {
			ob[k] = v
		}
		ob["tag"] = outTag
		outbounds = append(outbounds, ob)
		rules = append(rules, map[string]any{
			"type":        "field",
			"inboundTag":  []string{inTag},
			"outboundTag": outTag,
		})
	}
	return json.Marshal(map[string]any{
		"log":       map[string]any{"loglevel": logLevel},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
	})
}

// FreePorts reserves n free loopback TCP ports.
func FreePorts(n int) ([]int, error) {
	ls := make([]net.Listener, 0, n)
	defer func() {
		for _, l := range ls {
			l.Close()
		}
	}()
	ports := make([]int, 0, n)
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		ls = append(ls, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

// Instance is a running xray process.
type Instance struct {
	Ports   []int // Ports[i] is the SOCKS port of the i-th node of the batch
	cmd     *exec.Cmd
	exited  chan struct{}
	tail    *tailBuf
	cfgPath string
	once    sync.Once
}

// Start launches xray for the given nodes and waits until its inbounds accept connections.
// It fails fast when Xray rejects the config.
func Start(ctx context.Context, bin string, nodes []*model.Node, logLevel string) (*Instance, error) {
	ports, err := FreePorts(len(nodes))
	if err != nil {
		return nil, err
	}
	cfg, err := BuildConfig(nodes, ports, logLevel)
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp("", "xray-run-*.json")
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(cfg); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	f.Close()

	tail := &tailBuf{}
	cmd := exec.CommandContext(ctx, bin, "run", "-config", f.Name())
	cmd.Stdout, cmd.Stderr = tail, tail
	if err := cmd.Start(); err != nil {
		os.Remove(f.Name())
		return nil, err
	}
	in := &Instance{Ports: ports, cmd: cmd, exited: make(chan struct{}), tail: tail, cfgPath: f.Name()}
	go func() {
		_ = cmd.Wait()
		close(in.exited)
	}()
	if err := in.waitReady(ctx, 20*time.Second); err != nil {
		in.Stop()
		return nil, err
	}
	return in, nil
}

func (in *Instance) waitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	probe := []int{in.Ports[len(in.Ports)-1], in.Ports[0]}
	for {
		select {
		case <-in.exited:
			return fmt.Errorf("xray exited: %s", lastLine(in.tail.String()))
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		ready := true
		for _, p := range probe {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 200*time.Millisecond)
			if err != nil {
				ready = false
				break
			}
			c.Close()
		}
		if ready {
			// Give Xray a moment to die if a late start-up step rejects the config.
			select {
			case <-in.exited:
				return fmt.Errorf("xray exited: %s", lastLine(in.tail.String()))
			case <-time.After(150 * time.Millisecond):
				return nil
			}
		}
		if time.Now().After(deadline) {
			return errors.New("xray start timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Stop kills the process and removes its temporary config. It is safe to call twice.
func (in *Instance) Stop() {
	in.once.Do(func() {
		if in.cmd.Process != nil {
			_ = in.cmd.Process.Kill()
		}
		<-in.exited
		os.Remove(in.cfgPath)
	})
}

// Runner starts batches of nodes and isolates configs that Xray refuses to load.
type Runner struct {
	Bin      string
	LogLevel string
	Debug    bool
	Rejected atomic.Int64 // nodes Xray refused to load
}

// Each runs use() for the nodes, in as few Xray processes as possible. When Xray rejects a
// batch the batch is split in half until the offending config is found and dropped, so
// a single bad config never costs a whole batch. use() receives the nodes that were started
// together with the instance; inst.Ports[i] belongs to nodes[i].
func (r *Runner) Each(ctx context.Context, nodes []*model.Node, use func(inst *Instance, nodes []*model.Node)) {
	if len(nodes) == 0 || ctx.Err() != nil {
		return
	}
	inst, err := Start(ctx, r.Bin, nodes, r.LogLevel)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		if len(nodes) == 1 {
			r.Rejected.Add(1)
			if r.Debug {
				log.Printf("[xray] rejected %s %s:%d: %v", nodes[0].Proto, nodes[0].Host, nodes[0].Port, err)
			}
			return
		}
		mid := len(nodes) / 2
		r.Each(ctx, nodes[:mid], use)
		r.Each(ctx, nodes[mid:], use)
		return
	}
	defer inst.Stop()
	use(inst, nodes)
}

// tailBuf keeps the last few KB written to it (xray's console output).
type tailBuf struct {
	mu sync.Mutex
	b  []byte
}

func (t *tailBuf) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if len(t.b) > 4096 {
		t.b = t.b[len(t.b)-4096:]
	}
	return len(p), nil
}

func (t *tailBuf) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.b)
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func lastLine(s string) string {
	lines := nonEmptyLines(s)
	if len(lines) == 0 {
		return "(no output)"
	}
	l := lines[len(lines)-1]
	if len(l) > 300 {
		l = l[:300]
	}
	return l
}
