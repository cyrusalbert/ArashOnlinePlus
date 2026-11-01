// Package output renames the verified configs and writes all result files.
package output

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"arashonline/internal/geo"
	"arashonline/internal/model"
)

// Output file names.
const (
	FileMain       = "arashonline.txt"
	FileTop50Speed = "arashonline-top50speed.txt"
	FileTop50Ping  = "arashonline-top50ping.txt"
	FileHighValue  = "arashonline-highvalue.txt"
	FileBestLoc    = "arashonline-BestLoc.txt"
	FileHighSpeed  = "arashonline-highspeed.txt"
)

// Selection thresholds.
const (
	TopN              = 50
	HighValueMaxPing  = 200   // ms, inclusive
	HighValueMinSpeed = 800.0 // Mbps, exclusive
)

// Entry is a verified node together with its final remark and share link.
type Entry struct {
	Node   *model.Node
	Rank   int // 1-based position in the ping-sorted list
	Remark string
	Link   string
	Score  float64
}

// Score rates a config from 0 to 100, weighting ping and speed equally.
//
// Both parts are saturating curves so neither can dominate:
//
//	ping : 100 / (1 + ping/250)        50ms -> 83, 200ms -> 56, 1000ms -> 20
//	speed: 100 * v / (v + 200)         50   -> 20, 200   -> 50, 800    -> 80
func Score(pingMs int, mbps float64) float64 {
	p := 100 / (1 + float64(pingMs)/250)
	s := 100 * mbps / (mbps + 200)
	return 0.5*p + 0.5*s
}

// Remark renders: [rank] | [flag] | [ip:port] | [ping] | [speed]
func Remark(rank int, n *model.Node) string {
	return fmt.Sprintf("%d | %s | %s | %dms | %.1fMbps", rank, geo.Flag(n.Country), n.Addr, n.PingMs, n.SpeedMbps)
}

// Build sorts nodes by ping (ties: faster first), numbers them and renames their links.
func Build(nodes []*model.Node) []Entry {
	sorted := append([]*model.Node(nil), nodes...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].PingMs != sorted[j].PingMs {
			return sorted[i].PingMs < sorted[j].PingMs
		}
		return sorted[i].SpeedMbps > sorted[j].SpeedMbps
	})
	out := make([]Entry, len(sorted))
	for i, n := range sorted {
		r := Remark(i+1, n)
		out[i] = Entry{Node: n, Rank: i + 1, Remark: r, Link: n.ShareLink(r), Score: Score(n.PingMs, n.SpeedMbps)}
	}
	return out
}

// topBySpeed returns the n fastest entries (ties: lower ping first).
func topBySpeed(es []Entry, n int) []Entry {
	c := append([]Entry(nil), es...)
	sort.SliceStable(c, func(i, j int) bool {
		if c[i].Node.SpeedMbps != c[j].Node.SpeedMbps {
			return c[i].Node.SpeedMbps > c[j].Node.SpeedMbps
		}
		return c[i].Node.PingMs < c[j].Node.PingMs
	})
	if len(c) > n {
		c = c[:n]
	}
	return c
}

// topByPing returns the n lowest-ping entries. es must already be ping-sorted (see Build).
func topByPing(es []Entry, n int) []Entry {
	if len(es) > n {
		es = es[:n]
	}
	return append([]Entry(nil), es...)
}

// highValue keeps ping 0-200 ms AND speed above 800 Mbps, in ping order.
func highValue(es []Entry) []Entry {
	var out []Entry
	for _, e := range es {
		if e.Node.PingMs >= 0 && e.Node.PingMs <= HighValueMaxPing && e.Node.SpeedMbps > HighValueMinSpeed {
			out = append(out, e)
		}
	}
	return out
}

// bestPerCountry keeps the single highest-scoring entry of every known country,
// best country first. Configs whose country is unknown are left out.
func bestPerCountry(es []Entry) []Entry {
	best := map[string]Entry{}
	for _, e := range es {
		cc := e.Node.Country
		if cc == "" {
			continue
		}
		cur, ok := best[cc]
		if !ok || e.Score > cur.Score || (e.Score == cur.Score && e.Node.PingMs < cur.Node.PingMs) {
			best[cc] = e
		}
	}
	out := make([]Entry, 0, len(best))
	for _, e := range best {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Node.Country < out[j].Node.Country
	})
	return out
}

// Write renames the nodes and writes every output file into dir.
// It returns the number of lines per file.
func Write(dir string, nodes []*model.Node) (map[string]int, error) {
	all := Build(nodes)
	files := []struct {
		name    string
		entries []Entry
	}{
		{FileMain, all},
		{FileTop50Speed, topBySpeed(all, TopN)},
		{FileTop50Ping, topByPing(all, TopN)},
		{FileHighValue, highValue(all)},
		{FileBestLoc, bestPerCountry(all)},
		{FileHighSpeed, topBySpeed(all, TopN)},
	}
	counts := make(map[string]int, len(files))
	for _, f := range files {
		if err := writeLines(filepath.Join(dir, f.name), f.entries); err != nil {
			return nil, err
		}
		counts[f.name] = len(f.entries)
	}
	return counts, nil
}

func writeLines(path string, es []Entry) error {
	var b strings.Builder
	for _, e := range es {
		b.WriteString(e.Link)
		b.WriteByte('\n')
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
