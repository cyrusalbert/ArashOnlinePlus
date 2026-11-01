// Package model holds the types shared by every stage of the pipeline.
package model

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
)

// Node is one parsed proxy configuration.
type Node struct {
	Proto    string         // vmess | vless | trojan | ss | hysteria2
	Host     string         // server address as written in the link
	Port     int            // server port
	Link     string         // share link without the #remark part (not used for base64 vmess)
	VMess    map[string]any // decoded vmess JSON (base64 vmess links only)
	Outbound map[string]any // Xray outbound object (without tag)
	Key      string         // de-duplication key

	// Filled in by the tester.
	PingMs    int
	SpeedMbps float64
	Country   string // ISO 3166-1 alpha-2, empty when unknown
	Addr      string // ip:port shown in the remark
}

// ShareLink returns the share link with its remark replaced.
func (n *Node) ShareLink(remark string) string {
	if n.Proto == "vmess" && n.VMess != nil {
		m := make(map[string]any, len(n.VMess)+1)
		for k, v := range n.VMess {
			m[k] = v
		}
		m["ps"] = remark
		b, _ := json.Marshal(m)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	}
	return n.Link + "#" + EscapeFragment(remark)
}

// EscapeFragment percent-encodes a remark for use after '#'.
func EscapeFragment(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
