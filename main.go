// Command arashonline fetches V2Ray/Xray subscriptions, tests every config with Xray-core
// and writes the filtered, renamed and sorted result files.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"arashonline/internal/config"
	"arashonline/internal/fetch"
	"arashonline/internal/model"
	"arashonline/internal/output"
	"arashonline/internal/parse"
	"arashonline/internal/tester"
	"arashonline/internal/xray"
)

func main() {
	log.SetFlags(log.LstdFlags)
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	cfg := config.Load()
	flag.StringVar(&cfg.SourceList, "sources", cfg.SourceList, "path to the subscription list")
	flag.StringVar(&cfg.OutputDir, "out", cfg.OutputDir, "directory for the generated files")
	flag.StringVar(&cfg.XrayBin, "xray", cfg.XrayBin, "path to the xray binary")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	started := time.Now()

	version, err := xray.Version(cfg.XrayBin)
	if err != nil {
		return fmt.Errorf("cannot run xray-core (%s): %w", cfg.XrayBin, err)
	}
	log.Printf("[init] %s", version)

	// 1. Ingest subscriptions, parse, de-duplicate.
	sources, err := fetch.ReadSources(cfg.SourceList)
	if err != nil {
		return err
	}
	sources = append(sources, cfg.ExtraSources...)
	if len(sources) == 0 {
		return errors.New("no sources: fill sourcelist.txt or set the EXTRA_SOURCES secret")
	}
	raw := fetch.Collect(ctx, sources, cfg.FetchTimeout)
	nodes, st := parse.All(raw)
	log.Printf("[ingest] %d links -> %d unique configs (%d duplicates, %d unsupported, %d invalid)",
		st.Total, len(nodes), st.Duplicates, st.Unsupported, st.Invalid)
	nodes = dropUnsupportedHysteria(cfg, nodes)
	if len(nodes) == 0 {
		return errors.New("no usable configs found")
	}
	if cfg.MaxConfigs > 0 && len(nodes) > cfg.MaxConfigs {
		rand.Shuffle(len(nodes), func(i, j int) { nodes[i], nodes[j] = nodes[j], nodes[i] })
		nodes = nodes[:cfg.MaxConfigs]
		log.Printf("[ingest] MAX_CONFIGS: testing a random sample of %d", len(nodes))
	}

	// 2. Alive test + ping threshold, sorted by ping.
	runner := &xray.Runner{Bin: cfg.XrayBin, LogLevel: "error", Debug: cfg.Debug}
	t := tester.New(cfg, runner)
	alive := t.PingStage(ctx, nodes)
	log.Printf("[ping] %d alive with ping <= %dms (%d rejected by Xray)",
		len(alive), cfg.MaxPingMs, runner.Rejected.Load())
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// 3. Speed test + threshold, geolocation.
	final := t.SpeedStage(ctx, alive)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(final) == 0 {
		return errors.New("no config passed all tests; previous output files are left untouched")
	}
	sort.SliceStable(final, func(i, j int) bool { return final[i].PingMs < final[j].PingMs })

	// 4. Rename, sort and write every output file.
	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		return err
	}
	counts, err := output.Write(cfg.OutputDir, final)
	if err != nil {
		return err
	}
	for _, name := range []string{
		output.FileMain, output.FileTop50Speed, output.FileTop50Ping,
		output.FileHighValue, output.FileBestLoc, output.FileHighSpeed,
	} {
		log.Printf("[output] %-28s %d configs", name, counts[name])
	}
	log.Printf("[done] finished in %s", time.Since(started).Round(time.Second))
	return nil
}

// dropUnsupportedHysteria removes hysteria2 configs when the installed Xray-core build has no
// hysteria outbound (older releases), instead of letting every batch fail.
func dropUnsupportedHysteria(cfg config.Config, nodes []*model.Node) []*model.Node {
	has := false
	for _, n := range nodes {
		if n.Proto == "hysteria2" {
			has = true
			break
		}
	}
	if !has {
		return nodes
	}
	probe, err := parse.Link("hysteria2://probe@example.com:443?sni=example.com")
	if err == nil {
		err = xray.TestConfig(cfg.XrayBin, []*model.Node{probe})
	}
	if err == nil {
		return nodes
	}
	log.Printf("[init] this Xray-core cannot load hysteria2 outbounds (%v); skipping those configs", err)
	kept := make([]*model.Node, 0, len(nodes))
	for _, n := range nodes {
		if n.Proto != "hysteria2" {
			kept = append(kept, n)
		}
	}
	return kept
}
