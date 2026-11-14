package engine

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// ProxyEnvVar is how the TUI hands the proxy to the engine. The environment of
// a process is owner-readable only, while its argv (/proc/<pid>/cmdline) is
// world-readable, so proxy credentials never go on the command line.
const ProxyEnvVar = "BOUNTY_RUN_PROXY"

const proxySchemeHelp = "http://, https://, socks5:// or socks5h://"

var (
	proxySchemes   = map[string]bool{"http": true, "https": true, "socks5": true, "socks5h": true}
	proxyHostRE    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
	proxyDigitsRE  = regexp.MustCompile(`^[0-9.]+$`)
	proxyUserRE    = regexp.MustCompile(`^([A-Za-z0-9._~!$&'()*+,;=:-]|%[0-9A-Fa-f]{2})+$`)
	proxyPortRE    = regexp.MustCompile(`^[0-9]{1,5}$`)
	errProxyNoPort = errors.New("proxy URL needs a port (host:port)")
)

// ParseProxy ports runner/proxy.py parse: it validates a proxy URL with the
// same rules and returns the trimmed URL, or a user-facing error.
func ParseProxy(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty proxy URL")
	}
	for _, r := range s {
		if unicode.IsSpace(r) || r < 0x20 || r == 0x7f {
			return "", errors.New("proxy URL must not contain whitespace or control characters")
		}
	}
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		return "", errors.New("proxy needs a scheme: " + proxySchemeHelp)
	}
	if !proxySchemes[strings.ToLower(scheme)] {
		return "", fmt.Errorf("unsupported proxy scheme %q (use %s)", strings.ToLower(scheme), proxySchemeHelp)
	}
	if strings.ContainsAny(rest, "?#") {
		return "", errors.New("proxy URL must not have a query or fragment")
	}
	netloc, path, slash := strings.Cut(rest, "/")
	if slash && path != "" {
		return "", errors.New("proxy URL must not have a path")
	}
	hostport := netloc
	if i := strings.LastIndexByte(netloc, '@'); i >= 0 {
		userinfo := netloc[:i]
		hostport = netloc[i+1:]
		if userinfo == "" || !proxyUserRE.MatchString(userinfo) {
			return "", errors.New("invalid proxy credentials (percent-encode @ : and other special characters)")
		}
		if u, _, _ := strings.Cut(userinfo, ":"); u == "" {
			return "", errors.New("proxy credentials need a username")
		}
	}
	var portS string
	if strings.HasPrefix(hostport, "[") {
		end := strings.IndexByte(hostport, ']')
		if end < 0 {
			return "", errors.New("invalid proxy host: unterminated IPv6 literal")
		}
		host, tail := hostport[1:end], hostport[end+1:]
		if a, err := netip.ParseAddr(host); err != nil || !a.Is6() {
			return "", errors.New("invalid proxy host: bad IPv6 literal")
		}
		if !strings.HasPrefix(tail, ":") {
			return "", errProxyNoPort
		}
		portS = tail[1:]
	} else {
		i := strings.LastIndexByte(hostport, ':')
		if i < 0 {
			return "", errProxyNoPort
		}
		host := hostport[:i]
		portS = hostport[i+1:]
		if host == "" {
			return "", errors.New("proxy URL needs a host")
		}
		if proxyDigitsRE.MatchString(host) {
			if a, err := netip.ParseAddr(host); err != nil || !a.Is4() {
				return "", fmt.Errorf("invalid proxy host %q", host)
			}
		} else if len(host) > 253 || !proxyHostRE.MatchString(host) {
			return "", fmt.Errorf("invalid proxy host %q", host)
		}
	}
	if !proxyPortRE.MatchString(portS) {
		return "", errors.New("proxy port must be 1-65535")
	}
	if n, _ := strconv.Atoi(portS); n < 1 || n > 65535 {
		return "", errors.New("proxy port must be 1-65535")
	}
	return s, nil
}

// ProxyEnv is the extra environment for an engine launched with o (nil when
// no proxy is set).
func ProxyEnv(o Options) []string {
	if o.Proxy == "" {
		return nil
	}
	return []string{ProxyEnvVar + "=" + o.Proxy}
}
