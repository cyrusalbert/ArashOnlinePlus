package parse

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// streamOpts is the protocol-independent description of a transport + security layer.
type streamOpts struct {
	network     string // tcp | ws | grpc | httpupgrade | xhttp
	security    string // none | tls | reality
	headerType  string
	host        string
	path        string
	serviceName string
	mode        string // grpc: gun|multi, xhttp: auto|packet-up|stream-up|stream-one
	authority   string
	sni         string
	fp          string
	alpn        string
	pbk         string
	sid         string
	spx         string
	insecure    bool
	pcs         string // pinnedPeerCertSha256
	vcn         string // verifyPeerCertByName
	extra       string // xhttp "extra" JSON
}

func optsFromQuery(q url.Values) streamOpts {
	return streamOpts{
		network:     q.Get("type"),
		security:    strings.ToLower(q.Get("security")),
		headerType:  q.Get("headerType"),
		host:        q.Get("host"),
		path:        q.Get("path"),
		serviceName: q.Get("serviceName"),
		mode:        q.Get("mode"),
		authority:   q.Get("authority"),
		sni:         orDefault(q.Get("sni"), q.Get("peer")),
		fp:          q.Get("fp"),
		alpn:        q.Get("alpn"),
		pbk:         q.Get("pbk"),
		sid:         q.Get("sid"),
		spx:         q.Get("spx"),
		insecure:    truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure")),
		pcs:         q.Get("pcs"),
		vcn:         q.Get("vcn"),
		extra:       q.Get("extra"),
	}
}

// buildStream converts streamOpts into an Xray streamSettings object.
//
// It deliberately uses the long-standing "network" key: current Xray-core releases still
// accept it (the newer "method" key is an alias). allowInsecure is never emitted because
// Xray-core removed it; such configs are reported as unsupported instead.
func buildStream(o streamOpts) (map[string]any, error) {
	ss := map[string]any{}

	switch strings.ToLower(o.network) {
	case "", "tcp", "raw":
		ss["network"] = "tcp"
		if strings.EqualFold(o.headerType, "http") {
			req := map[string]any{"path": splitList(orDefault(o.path, "/"))}
			if o.host != "" {
				req["headers"] = map[string]any{"Host": splitList(o.host)}
			}
			ss["tcpSettings"] = map[string]any{
				"header": map[string]any{"type": "http", "request": req},
			}
		}
	case "ws", "websocket":
		ss["network"] = "ws"
		ws := map[string]any{"path": orDefault(o.path, "/")}
		if o.host != "" {
			ws["headers"] = map[string]any{"Host": o.host}
		}
		ss["wsSettings"] = ws
	case "grpc", "gun":
		ss["network"] = "grpc"
		g := map[string]any{"serviceName": o.serviceName}
		if strings.EqualFold(o.mode, "multi") {
			g["multiMode"] = true
		}
		if o.authority != "" {
			g["authority"] = o.authority
		}
		ss["grpcSettings"] = g
	case "httpupgrade":
		ss["network"] = "httpupgrade"
		h := map[string]any{"path": orDefault(o.path, "/")}
		if o.host != "" {
			h["host"] = o.host
		}
		ss["httpupgradeSettings"] = h
	case "xhttp", "splithttp":
		ss["network"] = "xhttp"
		x := map[string]any{
			"path": orDefault(o.path, "/"),
			"mode": orDefault(o.mode, "auto"),
		}
		if o.host != "" {
			x["host"] = o.host
		}
		if o.extra != "" {
			var extra map[string]any
			if err := json.Unmarshal([]byte(o.extra), &extra); err == nil {
				x["extra"] = extra
			}
		}
		ss["xhttpSettings"] = x
	default:
		return nil, fmt.Errorf("%w: transport %q", ErrUnsupported, o.network)
	}

	switch strings.ToLower(o.security) {
	case "", "none":
		ss["security"] = "none"
	case "tls":
		t, err := tlsSettings(o)
		if err != nil {
			return nil, err
		}
		ss["security"] = "tls"
		ss["tlsSettings"] = t
	case "reality":
		if o.pbk == "" {
			return nil, fmt.Errorf("%w: reality without public key", ErrUnsupported)
		}
		if n := ss["network"]; n != "tcp" && n != "xhttp" && n != "grpc" {
			return nil, fmt.Errorf("%w: reality over %v", ErrUnsupported, n)
		}
		r := map[string]any{
			"publicKey":   o.pbk,
			"fingerprint": orDefault(o.fp, "chrome"),
		}
		if o.sni != "" {
			r["serverName"] = o.sni
		}
		if o.sid != "" {
			r["shortId"] = o.sid
		}
		if o.spx != "" {
			r["spiderX"] = o.spx
		}
		ss["security"] = "reality"
		ss["realitySettings"] = r
	default:
		return nil, fmt.Errorf("%w: security %q", ErrUnsupported, o.security)
	}
	return ss, nil
}

func tlsSettings(o streamOpts) (map[string]any, error) {
	if o.insecure && o.pcs == "" {
		return nil, fmt.Errorf("%w: allowInsecure is not supported by current Xray-core", ErrUnsupported)
	}
	t := map[string]any{}
	sni := o.sni
	if sni == "" && o.host != "" && !strings.Contains(o.host, ",") {
		sni = o.host
	}
	if sni != "" {
		t["serverName"] = sni
	}
	if o.fp != "" {
		t["fingerprint"] = o.fp
	}
	if o.alpn != "" {
		t["alpn"] = splitList(o.alpn)
	}
	if o.pcs != "" {
		t["pinnedPeerCertSha256"] = o.pcs
	}
	if o.vcn != "" {
		t["verifyPeerCertByName"] = o.vcn
	}
	return t, nil
}

// DecodeBase64 decodes standard or URL-safe base64, with or without padding.
func DecodeBase64(s string) ([]byte, error) {
	s = strings.NewReplacer("\r", "", "\n", "", " ", "", "\t", "").Replace(s)
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, errors.New("empty base64")
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truthy(s string) bool {
	return s == "1" || strings.EqualFold(s, "true")
}

// jstr reads a JSON value as a trimmed string (vmess JSON mixes strings and numbers).
func jstr(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func jint(m map[string]any, k string) int {
	n, _ := strconv.Atoi(jstr(m, k))
	return n
}
