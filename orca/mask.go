package orca

import (
	"net"
	"strings"
)

type maskKind int

const (
	maskNickUserHost maskKind = iota
	maskExtbanAccount
	maskExtbanCertFP
	maskExtbanRealname
	maskExtbanCIDR
	maskExtbanCountry
	maskUnknown
)

type parsedMask struct {
	raw     string
	kind    maskKind
	nick    string
	user    string
	host    string
	value   string
	ipNet   *net.IPNet
}

// parseMask: a permissive parser that handles plain `nick!user@host` and
// the common UnrealIRCd extbans. Unknown shapes return maskUnknown.
func parseMask(s string) parsedMask {
	s = strings.TrimSpace(s)
	p := parsedMask{raw: s, kind: maskUnknown}
	if s == "" {
		return p
	}

	// ~kind:value extbans.
	if strings.HasPrefix(s, "~") {
		rest := s[1:]
		colon := strings.IndexByte(rest, ':')
		if colon < 0 {
			return p
		}
		kind := strings.ToLower(rest[:colon])
		val := rest[colon+1:]
		switch kind {
		case "a", "account":
			p.kind = maskExtbanAccount
			p.value = val
		case "cert", "certfp":
			p.kind = maskExtbanCertFP
			p.value = val
		case "real", "realname", "r":
			p.kind = maskExtbanRealname
			p.value = val
		case "country":
			p.kind = maskExtbanCountry
			p.value = strings.ToUpper(val)
		default:
			if ip, ipnet, err := net.ParseCIDR(val); err == nil {
				_ = ip
				p.kind = maskExtbanCIDR
				p.ipNet = ipnet
				p.value = val
			}
		}
		return p
	}

	// Plain nick!user@host.
	bang := strings.IndexByte(s, '!')
	at := strings.IndexByte(s, '@')
	if bang < 0 && at < 0 {
		p.kind = maskUnknown
		return p
	}
	if bang < 0 {
		p.nick = "*"
	} else {
		p.nick = s[:bang]
	}
	if at < 0 {
		p.user = "*"
		p.host = "*"
	} else {
		if bang >= 0 && bang < at {
			p.user = s[bang+1 : at]
		} else {
			p.user = "*"
		}
		p.host = s[at+1:]
	}
	if p.nick == "" {
		p.nick = "*"
	}
	if p.user == "" {
		p.user = "*"
	}
	if p.host == "" {
		p.host = "*"
	}
	// Also support pure CIDR `1.2.3.0/24` as a degenerate host-only mask.
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		p.kind = maskExtbanCIDR
		p.ipNet = ipnet
		p.value = s
		return p
	}
	p.kind = maskNickUserHost
	return p
}

func (p parsedMask) describe() string {
	switch p.kind {
	case maskNickUserHost:
		return "nick!user@host: " + p.nick + "!" + p.user + "@" + p.host
	case maskExtbanAccount:
		return "account == " + p.value
	case maskExtbanCertFP:
		return "TLS client cert fingerprint == " + p.value
	case maskExtbanRealname:
		return "realname matches " + p.value
	case maskExtbanCIDR:
		return "IP in CIDR " + p.value
	case maskExtbanCountry:
		return "country == " + p.value
	}
	return "unknown mask shape"
}

func (p parsedMask) matches(u map[string]any) bool {
	switch p.kind {
	case maskNickUserHost:
		return globMatch(p.nick, getString(u, "name")) &&
			globMatch(p.user, getString(u, "user", "username")) &&
			(globMatch(p.host, getString(u, "hostname")) ||
				globMatch(p.host, getString(u, "ip")))
	case maskExtbanAccount:
		return globMatch(p.value, getString(u, "user", "account"))
	case maskExtbanCertFP:
		return strings.EqualFold(p.value, getString(u, "tls", "certfp"))
	case maskExtbanRealname:
		return globMatch(p.value, getString(u, "user", "realname"))
	case maskExtbanCIDR:
		ipStr := getString(u, "ip")
		if ipStr == "" {
			return false
		}
		ip := net.ParseIP(ipStr)
		if ip == nil || p.ipNet == nil {
			return false
		}
		return p.ipNet.Contains(ip)
	case maskExtbanCountry:
		return strings.EqualFold(p.value, getString(u, "geoip", "country_code"))
	}
	return false
}

// globMatch: very small glob (`*`, `?`).
func globMatch(pattern, s string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	pl := []byte(strings.ToLower(pattern))
	sl := []byte(strings.ToLower(s))
	return doGlob(pl, sl, 0, 0)
}

func doGlob(p, s []byte, pi, si int) bool {
	for pi < len(p) {
		if p[pi] == '*' {
			for pi < len(p) && p[pi] == '*' {
				pi++
			}
			if pi == len(p) {
				return true
			}
			for k := si; k <= len(s); k++ {
				if doGlob(p, s, pi, k) {
					return true
				}
			}
			return false
		}
		if si >= len(s) {
			return false
		}
		if p[pi] == '?' || p[pi] == s[si] {
			pi++
			si++
			continue
		}
		return false
	}
	return si == len(s)
}
