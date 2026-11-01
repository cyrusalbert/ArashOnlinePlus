package tester

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func socksURL(port int) *url.URL {
	return &url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", port)}
}

// proxyClient returns an HTTP client that sends everything through the SOCKS port.
// Hostnames are resolved by the remote side, never locally.
func proxyClient(port int, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyURL(socksURL(port)),
		DisableCompression:    true,
		MaxIdleConns:          4,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func probe(ctx context.Context, c *http.Client, target string) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	d := time.Since(start)
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if strings.HasSuffix(target, "generate_204") {
		ok = resp.StatusCode == http.StatusNoContent
	}
	if !ok {
		return 0, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return d, nil
}

// measurePing reports the latency in ms. The first request (alive check) pays for DNS, TCP
// and TLS through the proxy, so the best of the follow-up requests on the same connection
// is used; that approximates the real round trip.
func (t *Tester) measurePing(ctx context.Context, port, samples int) (int, error) {
	c := proxyClient(port, t.cfg.PingTimeout)
	defer c.CloseIdleConnections()

	best, err := probe(ctx, c, t.cfg.PingURL)
	if err != nil {
		return 0, err
	}
	for i := 0; i < samples && ctx.Err() == nil; i++ {
		if d, err := probe(ctx, c, t.cfg.PingURL); err == nil && d < best {
			best = d
		}
	}
	ms := int(best / time.Millisecond)
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}

// measureSpeed downloads from several parallel streams and returns the aggregate rate in Mbps,
// ignoring the warm-up period. It aborts early when the rate is clearly below the threshold.
func (t *Tester) measureSpeed(ctx context.Context, port int) (float64, error) {
	cfg := t.cfg
	tr := &http.Transport{
		Proxy:               http.ProxyURL(socksURL(port)),
		DisableCompression:  true,
		MaxIdleConnsPerHost: cfg.SpeedStreams,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	ctx, cancel := context.WithTimeout(ctx, cfg.SpeedDuration+8*time.Second)
	defer cancel()

	var total, firstNs atomic.Int64
	var wg sync.WaitGroup
	for s := 0; s < cfg.SpeedStreams; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			failures := 0
			for ctx.Err() == nil {
				u := cfg.SpeedURLs[(s+failures)%len(cfg.SpeedURLs)]
				n, err := download(ctx, client, u, &total, &firstNs)
				if err != nil && n == 0 {
					failures++
					if failures >= 2*len(cfg.SpeedURLs) {
						return
					}
				}
			}
		}(s)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	var (
		warmT time.Time
		warmB int64
		rate  float64
		have  bool
	)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
loop:
	for {
		select {
		case <-done:
			break loop
		case <-ctx.Done():
			break loop
		case now := <-ticker.C:
			f := firstNs.Load()
			if f == 0 {
				continue
			}
			elapsed := now.Sub(time.Unix(0, f))
			if warmT.IsZero() {
				if elapsed >= cfg.SpeedWarmup {
					warmT, warmB = now, total.Load()
				}
				continue
			}
			if win := now.Sub(warmT); win > 0 {
				rate = mbps(total.Load()-warmB, win)
				have = true
			}
			if have && elapsed >= cfg.SpeedProbe && rate < cfg.MinSpeedMbps {
				break loop // clearly too slow, stop wasting time
			}
			if elapsed >= cfg.SpeedDuration {
				break loop
			}
		}
	}
	cancel()
	wg.Wait()

	if !have {
		return 0, errors.New("no measurable download")
	}
	return rate, nil
}

func download(ctx context.Context, c *http.Client, target string, total, first *atomic.Int64) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	buf := make([]byte, 128*1024)
	var got int64
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			got += int64(n)
			first.CompareAndSwap(0, time.Now().UnixNano())
			total.Add(int64(n))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return got, nil
			}
			return got, err
		}
	}
}

func mbps(bytes int64, d time.Duration) float64 {
	return float64(bytes) * 8 / d.Seconds() / 1e6
}
