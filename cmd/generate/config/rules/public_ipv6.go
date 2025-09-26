package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

// PublicIPv6 detects public IPv6 addresses (excludes private/reserved ranges via allowlist)
func PublicIPv6() *config.Rule {
	// IPv4 (for IPv4-embedded IPv6)
	ipv4Octet := `(?:25[0-5]|2[0-4]\d|1?\d{1,2})`
	ipv4Addr := `(?:` + ipv4Octet + `\.){3}` + ipv4Octet

	hextet := `[0-9a-f]{1,4}`

	// IPv6 core (non-capturing internally)
	ipv6Core := "" +
		"(?:" +
		"(?:" + hextet + ":){7}" + hextet + "|" +
		"(?:" + hextet + ":){1,7}:|" +
		"(?:" + hextet + ":){1,6}:" + hextet + "|" +
		"(?:" + hextet + ":){1,5}(?::" + hextet + "){1,2}|" +
		"(?:" + hextet + ":){1,4}(?::" + hextet + "){1,3}|" +
		"(?:" + hextet + ":){1,3}(?::" + hextet + "){1,4}|" +
		"(?:" + hextet + ":){1,2}(?::" + hextet + "){1,5}|" +
		"" + hextet + ":(?::" + hextet + "){1,6}|" +
		":(?::" + hextet + "){1,7}" +
		")"

	ipv6WithV4 := "" +
		"(?:" +
		"(?:" + hextet + ":){1,4}" + ipv4Addr + "|" +
		"::(?:" + hextet + ":){0,3}" + ipv4Addr +
		")"

	core := "(?:" + ipv6Core + "|" + ipv6WithV4 + ")"

	// Capture the IPv6 itself; optionally consume a trailing ']' so the generator’s terminator check passes for bracketed forms.
	regex := "(" + core + ")(?:\\])?"

	r := config.Rule{
		Description: "Public IPv6 address",
		RuleID:      "public-ipv6-address",
		Regex:       generateUniqueTokenRegex(regex, true),
		// SecretGroup stays default (first capture)
		Keywords: nil,
		Tags:     []string{"ip", "ipv6", "infrastructure"},
		Allowlist: config.Allowlist{
			Regexes: []*regexp.Regexp{
				// Unspecified and loopback
				regexp.MustCompile(`(?i)^::$`),
				regexp.MustCompile(`(?i)^::1$`),

				// ULA fc00::/7
				regexp.MustCompile(`(?i)^f[c-d][0-9a-f]{0,2}:`),

				// Link-local fe80::/10
				regexp.MustCompile(`(?i)^fe80:`),

				// Site-local (deprecated) fec0::/10
				regexp.MustCompile(`(?i)^fec0:`),

				// Multicast ff00::/8
				regexp.MustCompile(`(?i)^ff[0-9a-f]{2}:`),

				// IPv4-mapped (::ffff:0:0/96)
				regexp.MustCompile(`(?i)^::ffff:`),

				// Documentation 2001:db8::/32
				regexp.MustCompile(`(?i)^2001:db8:`),
			},
		},
	}

	truePositives := []string{
		"2001:4860:4860::8888",
		"2606:4700:4700::1111",
		"2a00:1450:4009:80b::200e",
		"[2a03:2880:f10d:83:face:b00c::25de]",
		"2001:db9::1",
	}
	falsePositives := []string{
		"::",
		"::1",
		"fe80::1",
		"ff02::1",
		"fc00::1",
		"fd12:3456::1",
		"fec0::1",
		"::ffff:192.0.2.1",
		"2001:db8::1",
	}

	return validate(r, truePositives, falsePositives)
}