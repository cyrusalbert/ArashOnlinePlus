// Package fetch reads sourcelist.txt and downloads every subscription.
package fetch

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"arashonline/internal/parse"
)

// ReadSources returns the non-empty, non-comment lines of the source list.
// A missing file is not an error (sources may come from EXTRA_SOURCES instead).
func ReadSources(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// Collect downloads every subscription URL and returns all share links found.
// Lines that already are share links are passed through unchanged.
func Collect(ctx context.Context, sources []string, timeout time.Duration) []string {
	client := &http.Client{Timeout: timeout}
	sem := make(chan struct{}, 8)
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		all []string
	)
	for _, s := range sources {
		switch {
		case parse.HasKnownScheme(s):
			mu.Lock()
			all = append(all, s)
			mu.Unlock()
		case strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://"):
			wg.Add(1)
			go func(src string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				body, err := download(ctx, client, src)
				if err != nil {
					log.Printf("[fetch] %s: %v", mask(src), err)
					return
				}
				links := ExtractLinks(body)
				log.Printf("[fetch] %s: %d configs", mask(src), len(links))
				mu.Lock()
				all = append(all, links...)
				mu.Unlock()
			}(s)
		default:
			log.Printf("[fetch] ignoring unrecognised source line")
		}
	}
	wg.Wait()
	return all
}

// ExtractLinks accepts a plain-text or base64 subscription body.
func ExtractLinks(body []byte) []string {
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	if text == "" {
		return nil
	}
	if !strings.Contains(text, "://") {
		if dec, err := parse.DecodeBase64(text); err == nil {
			text = string(dec)
		}
	}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if parse.HasKnownScheme(line) {
			out = append(out, line)
		}
	}
	return out
}

func download(ctx context.Context, c *http.Client, target string) ([]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "v2rayN/7.0.0")
		resp, err := c.Do(req)
		if err == nil {
			b, rerr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			resp.Body.Close()
			switch {
			case rerr != nil:
				err = rerr
			case resp.StatusCode != http.StatusOK:
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			default:
				return b, nil
			}
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt) * 2 * time.Second):
		}
	}
	return nil, lastErr
}

// mask hides everything but the host so secret subscription tokens never reach public logs.
func mask(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<source>"
	}
	return u.Scheme + "://" + u.Host + "/..."
}
