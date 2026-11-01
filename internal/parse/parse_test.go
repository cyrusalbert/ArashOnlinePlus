package parse

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const uuid = "11111111-2222-3333-4444-555555555555"

func TestVLESSReality(t *testing.T) {
	n, err := Link("vless://" + uuid + "@example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=abc&sid=01&type=tcp&flow=xtls-rprx-vision#old")
	if err != nil {
		t.Fatal(err)
	}
	if n.Proto != "vless" || n.Host != "example.com" || n.Port != 443 {
		t.Fatalf("unexpected node: %s %s %d", n.Proto, n.Host, n.Port)
	}
	if got := n.ShareLink("1 | x"); !strings.HasSuffix(got, "#1%20%7C%20x") {
		t.Fatalf("unexpected renamed link: %s", got)
	}
}

func TestVMessRename(t *testing.T) {
	js := `{"v":"2","ps":"old","add":"1.2.3.4","port":"443","id":"` + uuid + `","aid":"0","net":"ws","host":"h.example.com","path":"/ws","tls":"tls","sni":"h.example.com"}`
	n, err := Link("vmess://" + base64.StdEncoding.EncodeToString([]byte(js)))
	if err != nil {
		t.Fatal(err)
	}
	if n.Host != "1.2.3.4" || n.Port != 443 {
		t.Fatalf("unexpected address %s:%d", n.Host, n.Port)
	}
	link := n.ShareLink("new remark")
	dec, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(dec, &m); err != nil {
		t.Fatal(err)
	}
	if m["ps"] != "new remark" {
		t.Fatalf("remark not replaced: %v", m["ps"])
	}
}

func TestShadowsocksSIP002(t *testing.T) {
	ui := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret"))
	n, err := Link("ss://" + ui + "@5.6.7.8:8388#name")
	if err != nil {
		t.Fatal(err)
	}
	if n.Host != "5.6.7.8" || n.Port != 8388 {
		t.Fatalf("unexpected address %s:%d", n.Host, n.Port)
	}
}

func TestHysteria2(t *testing.T) {
	n, err := Link("hysteria2://pw@example.com:8443,20000-30000?sni=example.com&obfs=salamander&obfs-password=x#h")
	if err != nil {
		t.Fatal(err)
	}
	if n.Port != 8443 || n.Proto != "hysteria2" {
		t.Fatalf("unexpected node: %s %d", n.Proto, n.Port)
	}
}

func TestUnsupportedConfigsAreRejected(t *testing.T) {
	for _, l := range []string{
		"trojan://pw@example.com:443?security=tls&allowInsecure=1",
		"vless://" + uuid + "@example.com:80?encryption=none&security=none",
		"hysteria2://pw@example.com:443?insecure=1",
	} {
		if _, err := Link(l); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("expected ErrUnsupported for %s, got %v", l, err)
		}
	}
}

func TestAllDeduplicates(t *testing.T) {
	base := "trojan://pw@example.com:443?security=tls&sni=example.com"
	nodes, st := All([]string{base + "#a", base + "#b"})
	if len(nodes) != 1 || st.Duplicates != 1 {
		t.Fatalf("got %d nodes, %d duplicates", len(nodes), st.Duplicates)
	}
}
