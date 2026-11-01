// Package geo finds the country of a config and turns it into a flag emoji.
package geo

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Public endpoints that answer "where is the caller?". They are queried THROUGH the proxy,
// so the result is the real exit country (which is what matters for CDN-fronted servers).
var exitEndpoints = []string{
	"https://api.country.is/",
	"http://ip-api.com/json/?fields=status,countryCode",
	"https://ipwho.is/",
}

// ExitCountry asks the endpoints (via the given proxy client) for the exit country code.
func ExitCountry(ctx context.Context, c *http.Client) string {
	for _, u := range exitEndpoints {
		if cc := fetchCountry(ctx, c, u); cc != "" {
			return cc
		}
	}
	return ""
}

// CountryOfIP looks up the country of an IP address directly (no proxy).
func CountryOfIP(ctx context.Context, ip string) string {
	c := &http.Client{Timeout: 6 * time.Second}
	return fetchCountry(ctx, c, "https://api.country.is/"+ip)
}

func fetchCountry(ctx context.Context, c *http.Client, target string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := c.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var m map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&m); err != nil {
		return ""
	}
	for _, k := range []string{"country", "countryCode", "country_code"} {
		if s, ok := m[k].(string); ok && len(s) == 2 {
			return strings.ToUpper(s)
		}
	}
	return ""
}

// ResolveIP resolves a hostname to one IP (IPv4 preferred). Empty string on failure.
func ResolveIP(ctx context.Context, host string) string {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ips[0].IP.String()
}

// Flag converts an ISO 3166-1 alpha-2 code into a flag emoji; unknown codes give a white flag.
func Flag(cc string) string {
	r := []rune(strings.ToUpper(strings.TrimSpace(cc)))
	if len(r) != 2 || r[0] < 'A' || r[0] > 'Z' || r[1] < 'A' || r[1] > 'Z' {
		return "\U0001F3F3\uFE0F"
	}
	return string([]rune{0x1F1E6 + (r[0] - 'A'), 0x1F1E6 + (r[1] - 'A')})
}
