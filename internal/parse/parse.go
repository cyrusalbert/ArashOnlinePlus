// Package parse turns share links into Nodes with a ready-to-use Xray outbound.
package parse

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"arashonline/internal/model"
)

// ErrUnsupported marks links that are valid but cannot be tested with current Xray-core.
var ErrUnsupported = errors.New("unsupported")

var knownSchemes = []string{"vmess://", "vless://", "trojan://", "ss://", "hysteria2://", "hy2://"}

// HasKnownScheme reports whether s starts with one of the supported share-link schemes.
func HasKnownScheme(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	for _, p := range knownSchemes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// Stats summarises a parsing run.
type Stats struct {
	Total, Parsed, Duplicates, Unsupported, Invalid int
}

// All parses every link and removes duplicates (same server, credentials and transport).
func All(raw []string) ([]*model.Node, Stats) {
	var st Stats
	seen := make(map[string]struct{}, len(raw))
	nodes := make([]*model.Node, 0, len(raw))
	for _, r := range raw {
		st.Total++
		n, err := Link(r)
		if err != nil {
			if errors.Is(err, ErrUnsupported) {
				st.Unsupported++
			} else {
				st.Invalid++
			}
			continue
		}
		if _, dup := seen[n.Key]; dup {
			st.Duplicates++
			continue
		}
		seen[n.Key] = struct{}{}
		nodes = append(nodes, n)
		st.Parsed++
	}
	return nodes, st
}

// Link parses one share link.
func Link(raw string) (*model.Node, error) {
	raw = strings.TrimSpace(raw)
	var (
		n   *model.Node
		err error
	)
	switch l := strings.ToLower(raw); {
	case strings.HasPrefix(l, "vmess://"):
		n, err = parseVMess(raw)
	case strings.HasPrefix(l, "vless://"):
		n, err = parseVLESS(raw)
	case strings.HasPrefix(l, "trojan://"):
		n, err = parseTrojan(raw)
	case strings.HasPrefix(l, "ss://"):
		n, err = parseSS(raw)
	case strings.HasPrefix(l, "hysteria2://"), strings.HasPrefix(l, "hy2://"):
		n, err = parseHysteria2(raw)
	default:
		return nil, fmt.Errorf("%w: unknown scheme", ErrUnsupported)
	}
	if err != nil {
		return nil, err
	}
	if n.Host == "" || n.Port < 1 || n.Port > 65535 {
		return nil, errors.New("invalid server address")
	}
	b, err := json.Marshal(n.Outbound)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(b)
	n.Key = hex.EncodeToString(sum[:])
	return n, nil
}

func stripFragment(s string) string {
	if i := strings.Index(s, "#"); i >= 0 {
		return s[:i]
	}
	return s
}

func userName(u *url.URL) string {
	if u.User == nil {
		return ""
	}
	s := u.User.Username()
	if p, ok := u.User.Password(); ok {
		s += ":" + p
	}
	return s
}

func parseAuthority(raw string) (*url.URL, string, int, error) {
	u, err := url.Parse(stripFragment(raw))
	if err != nil {
		return nil, "", 0, err
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || u.Hostname() == "" {
		return nil, "", 0, errors.New("invalid host:port")
	}
	return u, u.Hostname(), port, nil
}

// ---------------------------------------------------------------- vmess

func parseVMess(raw string) (*model.Node, error) {
	payload := stripFragment(strings.TrimSpace(raw[len("vmess://"):]))
	if strings.Contains(payload, "@") {
		return parseVMessURL(raw)
	}
	b, err := DecodeBase64(payload)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	host, id, port := jstr(m, "add"), jstr(m, "id"), jint(m, "port")
	if host == "" || id == "" {
		return nil, errors.New("incomplete vmess config")
	}
	o := streamOpts{
		network:    jstr(m, "net"),
		security:   strings.ToLower(jstr(m, "tls")),
		headerType: jstr(m, "type"),
		host:       jstr(m, "host"),
		path:       jstr(m, "path"),
		sni:        jstr(m, "sni"),
		fp:         jstr(m, "fp"),
		alpn:       jstr(m, "alpn"),
		insecure:   truthy(jstr(m, "allowInsecure")) || truthy(jstr(m, "insecure")),
		pcs:        jstr(m, "pcs"),
		vcn:        jstr(m, "vcn"),
	}
	if strings.EqualFold(o.network, "grpc") {
		o.serviceName, o.mode, o.authority = o.path, o.headerType, o.host
	}
	ss, err := buildStream(o)
	if err != nil {
		return nil, err
	}
	user := map[string]any{"id": id, "security": orDefault(jstr(m, "scy"), "auto")}
	if aid := jint(m, "aid"); aid > 0 {
		user["alterId"] = aid
	}
	return &model.Node{
		Proto: "vmess", Host: host, Port: port, VMess: m,
		Outbound: map[string]any{
			"protocol": "vmess",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": host, "port": port, "users": []any{user},
			}}},
			"streamSettings": ss,
		},
	}, nil
}

// parseVMessURL handles the vmess://uuid@host:port?... form used by some panels.
func parseVMessURL(raw string) (*model.Node, error) {
	u, host, port, err := parseAuthority(raw)
	if err != nil {
		return nil, err
	}
	id := userName(u)
	if id == "" {
		return nil, errors.New("missing uuid")
	}
	q := u.Query()
	ss, err := buildStream(optsFromQuery(q))
	if err != nil {
		return nil, err
	}
	user := map[string]any{"id": id, "security": orDefault(q.Get("encryption"), "auto")}
	return &model.Node{
		Proto: "vmess", Host: host, Port: port, Link: stripFragment(raw),
		Outbound: map[string]any{
			"protocol": "vmess",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": host, "port": port, "users": []any{user},
			}}},
			"streamSettings": ss,
		},
	}, nil
}

// ---------------------------------------------------------------- vless

func parseVLESS(raw string) (*model.Node, error) {
	u, host, port, err := parseAuthority(raw)
	if err != nil {
		return nil, err
	}
	id := userName(u)
	if id == "" {
		return nil, errors.New("missing uuid")
	}
	q := u.Query()
	enc := orDefault(q.Get("encryption"), "none")
	o := optsFromQuery(q)
	if enc == "none" && (o.security == "" || o.security == "none") {
		// Current Xray-core refuses plaintext VLESS to public addresses.
		return nil, fmt.Errorf("%w: plaintext VLESS", ErrUnsupported)
	}
	ss, err := buildStream(o)
	if err != nil {
		return nil, err
	}
	user := map[string]any{"id": id, "encryption": enc}
	if f := q.Get("flow"); f != "" {
		user["flow"] = f
	}
	return &model.Node{
		Proto: "vless", Host: host, Port: port, Link: stripFragment(raw),
		Outbound: map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": host, "port": port, "users": []any{user},
			}}},
			"streamSettings": ss,
		},
	}, nil
}

// ---------------------------------------------------------------- trojan

func parseTrojan(raw string) (*model.Node, error) {
	u, host, port, err := parseAuthority(raw)
	if err != nil {
		return nil, err
	}
	pass := userName(u)
	if pass == "" {
		return nil, errors.New("missing password")
	}
	o := optsFromQuery(u.Query())
	if o.security == "" {
		o.security = "tls" // trojan links default to TLS
	}
	if o.security == "none" {
		return nil, fmt.Errorf("%w: plaintext trojan", ErrUnsupported)
	}
	ss, err := buildStream(o)
	if err != nil {
		return nil, err
	}
	return &model.Node{
		Proto: "trojan", Host: host, Port: port, Link: stripFragment(raw),
		Outbound: map[string]any{
			"protocol": "trojan",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": host, "port": port, "password": pass,
			}}},
			"streamSettings": ss,
		},
	}, nil
}

// ---------------------------------------------------------------- shadowsocks

var ssMethods = map[string]bool{
	"aes-128-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "chacha20-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
	"2022-blake3-chacha20-poly1305": true,
	"none": true, "plain": true,
}

func splitOnce(s, sep string) (string, string) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):]
	}
	return s, ""
}

func parseSS(raw string) (*model.Node, error) {
	base := stripFragment(raw)
	body := base[len("ss://"):]
	query := ""
	if i := strings.Index(body, "?"); i >= 0 {
		query, body = body[i+1:], body[:i]
	}
	body = strings.TrimRight(body, "/")

	var method, password, hostport string
	if at := strings.LastIndex(body, "@"); at >= 0 {
		// SIP002: userinfo@host:port, userinfo is base64(method:password) or plain.
		userinfo := body[:at]
		hostport = body[at+1:]
		if dec, err := DecodeBase64(userinfo); err == nil && strings.Contains(string(dec), ":") {
			method, password = splitOnce(string(dec), ":")
		} else {
			ui, uerr := url.PathUnescape(userinfo)
			if uerr != nil {
				ui = userinfo
			}
			if !strings.Contains(ui, ":") {
				return nil, errors.New("bad shadowsocks userinfo")
			}
			method, password = splitOnce(ui, ":")
		}
	} else {
		// Legacy: base64(method:password@host:port)
		dec, err := DecodeBase64(body)
		if err != nil {
			return nil, err
		}
		s := string(dec)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return nil, errors.New("bad shadowsocks link")
		}
		hostport = s[at+1:]
		method, password = splitOnce(s[:at], ":")
	}

	if q, err := url.ParseQuery(query); err == nil && q.Get("plugin") != "" {
		return nil, fmt.Errorf("%w: shadowsocks plugin", ErrUnsupported)
	}
	method = strings.ToLower(method)
	if !ssMethods[method] {
		return nil, fmt.Errorf("%w: shadowsocks method %q", ErrUnsupported, method)
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	return &model.Node{
		Proto: "ss", Host: host, Port: port, Link: base,
		Outbound: map[string]any{
			"protocol": "shadowsocks",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": host, "port": port, "method": method, "password": password,
			}}},
		},
	}, nil
}

// ---------------------------------------------------------------- hysteria2

// Port lists such as host:443,20000-30000 (port hopping) are reduced to the first port.
var portListRe = regexp.MustCompile(`(:\d+)[,\-][\d,\-]+`)

func parseHysteria2(raw string) (*model.Node, error) {
	base := stripFragment(raw)
	idx := strings.Index(base, "://")
	rest := base[idx+3:]
	authEnd := len(rest)
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		authEnd = i
	}
	authority := portListRe.ReplaceAllString(rest[:authEnd], "$1")
	u, err := url.Parse("hysteria2://" + authority + rest[authEnd:])
	if err != nil {
		return nil, err
	}
	auth := userName(u)
	if auth == "" {
		return nil, errors.New("missing hysteria2 password")
	}
	port := 443
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return nil, err
		}
	}
	q := u.Query()
	insecure := truthy(q.Get("insecure")) || truthy(q.Get("allowInsecure"))
	pin := q.Get("pinSHA256")
	if insecure && pin == "" {
		return nil, fmt.Errorf("%w: insecure TLS is not supported by current Xray-core", ErrUnsupported)
	}

	tls := map[string]any{"alpn": []string{"h3"}}
	if sni := orDefault(q.Get("sni"), q.Get("peer")); sni != "" {
		tls["serverName"] = sni
	}
	if pin != "" {
		tls["pinnedPeerCertSha256"] = pin
	}
	ss := map[string]any{
		"network":          "hysteria",
		"security":         "tls",
		"tlsSettings":      tls,
		"hysteriaSettings": map[string]any{"version": 2, "auth": auth},
	}
	if obfs := q.Get("obfs"); obfs != "" {
		if !strings.EqualFold(obfs, "salamander") {
			return nil, fmt.Errorf("%w: hysteria2 obfs %q", ErrUnsupported, obfs)
		}
		ss["finalmask"] = map[string]any{"udp": []any{map[string]any{
			"type":     "salamander",
			"settings": map[string]any{"password": q.Get("obfs-password")},
		}}}
	}
	return &model.Node{
		Proto: "hysteria2", Host: u.Hostname(), Port: port, Link: base,
		Outbound: map[string]any{
			"protocol":       "hysteria",
			"settings":       map[string]any{"version": 2, "address": u.Hostname(), "port": port},
			"streamSettings": ss,
		},
	}, nil
}
