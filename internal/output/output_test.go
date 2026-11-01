package output

import (
	"strings"
	"testing"

	"arashonline/internal/model"
)

func node(ping int, speed float64, cc string) *model.Node {
	return &model.Node{Proto: "ss", Link: "ss://x@1.1.1.1:1", PingMs: ping, SpeedMbps: speed, Country: cc, Addr: "1.1.1.1:1"}
}

func TestBuildSortsAndNumbersByPing(t *testing.T) {
	es := Build([]*model.Node{node(300, 100, "DE"), node(50, 900, "US"), node(150, 850, "DE")})
	if es[0].Node.PingMs != 50 || es[0].Rank != 1 || es[2].Node.PingMs != 300 {
		t.Fatalf("unexpected order")
	}
	if !strings.HasPrefix(es[0].Remark, "1 | ") || !strings.HasSuffix(es[0].Remark, " | 1.1.1.1:1 | 50ms | 900.0Mbps") {
		t.Fatalf("unexpected remark: %s", es[0].Remark)
	}
}

func TestSelections(t *testing.T) {
	es := Build([]*model.Node{node(300, 100, "DE"), node(50, 900, "US"), node(150, 850, "DE"), node(250, 900, "FR")})

	if got := len(highValue(es)); got != 2 {
		t.Fatalf("highValue: got %d, want 2", got)
	}
	if top := topBySpeed(es, 2); len(top) != 2 || top[0].Node.PingMs != 50 {
		t.Fatalf("topBySpeed unexpected")
	}
	best := bestPerCountry(es)
	if len(best) != 3 {
		t.Fatalf("bestPerCountry: got %d countries, want 3", len(best))
	}
	for _, e := range best {
		if e.Node.Country == "DE" && e.Node.PingMs != 150 {
			t.Fatalf("wrong DE winner: %d ms", e.Node.PingMs)
		}
	}
}

func TestScoreRewardsBoth(t *testing.T) {
	if !(Score(50, 500) > Score(500, 500)) || !(Score(50, 500) > Score(50, 100)) {
		t.Fatal("score must improve with lower ping and higher speed")
	}
}
