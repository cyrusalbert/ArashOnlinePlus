// Package tester runs the liveness/ping stage and the download-speed stage.
package tester

import (
	"context"
	"log"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"arashonline/internal/config"
	"arashonline/internal/geo"
	"arashonline/internal/model"
	"arashonline/internal/xray"
)

// Tester holds the settings and the Xray runner used by both stages.
type Tester struct {
	cfg    config.Config
	runner *xray.Runner
}

// New creates a Tester.
func New(cfg config.Config, r *xray.Runner) *Tester {
	return &Tester{cfg: cfg, runner: r}
}

// PingStage tests all nodes in parallel through Xray, drops dead ones and anything slower than
// MaxPingMs, and returns the survivors sorted by ping (lowest first).
func (t *Tester) PingStage(ctx context.Context, nodes []*model.Node) []*model.Node {
	var (
		mu    sync.Mutex
		alive []*model.Node
	)
	total := len(nodes)
	for start := 0; start < total && ctx.Err() == nil; start += t.cfg.BatchSize {
		end := min(start+t.cfg.BatchSize, total)
		t.runner.Each(ctx, nodes[start:end], func(inst *xray.Instance, ns []*model.Node) {
			sem := make(chan struct{}, t.cfg.PingConcurrency)
			var wg sync.WaitGroup
			for i, n := range ns {
				i, n := i, n
				sem <- struct{}{}
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					ms, err := t.measurePing(ctx, inst.Ports[i], t.cfg.PingSamples)
					if err != nil || ms > t.cfg.MaxPingMs {
						return
					}
					n.PingMs = ms
					mu.Lock()
					alive = append(alive, n)
					mu.Unlock()
				}()
			}
			wg.Wait()
		})
		mu.Lock()
		log.Printf("[ping] %d/%d tested, %d alive", end, total, len(alive))
		mu.Unlock()
	}
	sort.SliceStable(alive, func(i, j int) bool { return alive[i].PingMs < alive[j].PingMs })
	return alive
}

// SpeedStage takes the lowest-ping candidates and, one by one (or SpeedConcurrency at a time),
// re-measures the ping on an idle connection, measures the download speed and finds the
// country. Only configs with ping <= MaxPingMs and speed >= MinSpeedMbps survive.
func (t *Tester) SpeedStage(ctx context.Context, cands []*model.Node) []*model.Node {
	if t.cfg.MaxSpeedCandidates > 0 && len(cands) > t.cfg.MaxSpeedCandidates {
		log.Printf("[speed] limiting to the %d lowest-ping candidates (of %d)", t.cfg.MaxSpeedCandidates, len(cands))
		cands = cands[:t.cfg.MaxSpeedCandidates]
	}
	var (
		mu   sync.Mutex
		pass []*model.Node
	)
	total := len(cands)
	for start := 0; start < total && ctx.Err() == nil; start += t.cfg.BatchSize {
		end := min(start+t.cfg.BatchSize, total)
		t.runner.Each(ctx, cands[start:end], func(inst *xray.Instance, ns []*model.Node) {
			sem := make(chan struct{}, t.cfg.SpeedConcurrency)
			var wg sync.WaitGroup
			for i, n := range ns {
				if ctx.Err() != nil {
					break
				}
				i, n := i, n
				sem <- struct{}{}
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					if t.testOne(ctx, n, inst.Ports[i]) {
						mu.Lock()
						pass = append(pass, n)
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
		})
		mu.Lock()
		log.Printf("[speed] %d/%d tested, %d passed (>= %.0f Mbps)", end, total, len(pass), t.cfg.MinSpeedMbps)
		mu.Unlock()
	}
	return pass
}

func (t *Tester) testOne(ctx context.Context, n *model.Node, port int) bool {
	ms, err := t.measurePing(ctx, port, 3)
	if err != nil || ms > t.cfg.MaxPingMs {
		return false
	}
	speed, err := t.measureSpeed(ctx, port)
	if err != nil || speed < t.cfg.MinSpeedMbps {
		return false
	}
	n.PingMs = ms
	n.SpeedMbps = speed
	t.locate(ctx, n, port)
	log.Printf("[speed] ok %s %s:%d %dms %.0fMbps %s", n.Proto, n.Host, n.Port, n.PingMs, n.SpeedMbps, n.Country)
	return true
}

// locate fills n.Addr (ip:port) and n.Country.
func (t *Tester) locate(ctx context.Context, n *model.Node, port int) {
	ip := n.Host
	if net.ParseIP(ip) == nil && t.cfg.ResolveDomains {
		if r := geo.ResolveIP(ctx, n.Host); r != "" {
			ip = r
		}
	}
	n.Addr = net.JoinHostPort(ip, strconv.Itoa(n.Port))

	c := proxyClient(port, 6*time.Second)
	defer c.CloseIdleConnections()
	cc := geo.ExitCountry(ctx, c)
	if cc == "" && net.ParseIP(ip) != nil {
		cc = geo.CountryOfIP(ctx, ip)
	}
	n.Country = cc
}
