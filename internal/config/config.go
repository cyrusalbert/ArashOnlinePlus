// Package config reads every tunable from environment variables.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all settings. Every field can be overridden by an environment variable.
type Config struct {
	SourceList   string
	ExtraSources []string // EXTRA_SOURCES (newline separated), e.g. from a GitHub secret
	OutputDir    string
	XrayBin      string

	FetchTimeout time.Duration
	MaxConfigs   int // 0 = unlimited

	PingURL         string
	PingTimeout     time.Duration
	PingSamples     int
	MaxPingMs       int
	PingConcurrency int
	BatchSize       int // configs per Xray process

	SpeedURLs          []string
	SpeedDuration      time.Duration
	SpeedWarmup        time.Duration
	SpeedProbe         time.Duration // abort early if still below MinSpeedMbps after this long
	SpeedStreams       int
	MinSpeedMbps       float64
	SpeedConcurrency   int
	MaxSpeedCandidates int // lowest-ping candidates that get a speed test

	ResolveDomains bool
	Debug          bool
}

// Load builds the configuration from the environment.
func Load() Config {
	c := Config{
		SourceList:   str("SOURCE_LIST", "sourcelist.txt"),
		ExtraSources: lines("EXTRA_SOURCES"),
		OutputDir:    str("OUTPUT_DIR", "."),
		XrayBin:      str("XRAY_BIN", "xray"),

		FetchTimeout: secs("FETCH_TIMEOUT_SEC", 45),
		MaxConfigs:   integer("MAX_CONFIGS", 0),

		PingURL:         str("PING_URL", "https://www.gstatic.com/generate_204"),
		PingTimeout:     secs("PING_TIMEOUT_SEC", 5),
		PingSamples:     integer("PING_SAMPLES", 2),
		MaxPingMs:       integer("MAX_PING_MS", 3000),
		PingConcurrency: integer("PING_CONCURRENCY", 64),
		BatchSize:       integer("BATCH_SIZE", 200),

		SpeedURLs: list("SPEED_URLS", []string{
			"https://speed.cloudflare.com/__down?bytes=25000000",
			"https://cachefly.cachefly.net/50mb.test",
		}),
		SpeedDuration:      secs("SPEED_DURATION_SEC", 8),
		SpeedWarmup:        secs("SPEED_WARMUP_SEC", 1),
		SpeedProbe:         secs("SPEED_PROBE_SEC", 3),
		SpeedStreams:       integer("SPEED_STREAMS", 4),
		MinSpeedMbps:       float("MIN_SPEED_MBPS", 50),
		SpeedConcurrency:   integer("SPEED_CONCURRENCY", 1),
		MaxSpeedCandidates: integer("MAX_SPEED_CANDIDATES", 800),

		ResolveDomains: boolean("RESOLVE_DOMAINS", true),
		Debug:          boolean("DEBUG", false),
	}
	if c.BatchSize < 1 {
		c.BatchSize = 1
	}
	if c.PingConcurrency < 1 {
		c.PingConcurrency = 1
	}
	if c.SpeedConcurrency < 1 {
		c.SpeedConcurrency = 1
	}
	if c.SpeedStreams < 1 {
		c.SpeedStreams = 1
	}
	if c.PingSamples < 0 {
		c.PingSamples = 0
	}
	return c
}

func str(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func integer(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func float(key string, def float64) float64 {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func boolean(key string, def bool) bool {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func secs(key string, def int) time.Duration {
	return time.Duration(integer(key, def)) * time.Second
}

func list(key string, def []string) []string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

func lines(key string) []string {
	var out []string
	for _, l := range strings.Split(os.Getenv(key), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}
