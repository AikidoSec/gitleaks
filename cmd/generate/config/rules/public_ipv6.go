package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

// PublicIPv6PIICandidate detects public IPv6 addresses as PII candidates.
// Notes:
// - Does not rely on surrounding text/context.
// - Flags any public IPv6 address except private/reserved ranges and a small
//   set of well-known anycast resolver IPs that are highly unlikely to be PII.
// - Actual determination of PII should be verified (e.g., via whois) downstream.
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
		Description: "Public IPv6 address (PII candidate, verify via whois)",
		RuleID:      "public-ipv6-pii",
		Regex:       generateUniqueTokenRegex(regex, true),
		Keywords:    nil, // run globally
		Tags:        []string{"ip", "ipv6", "pii-candidate"},
		Allowlist: config.Allowlist{
			Regexes: []*regexp.Regexp{
				// Unspecified and loopback
				regexp.MustCompile(`(?i)^::$`),
				regexp.MustCompile(`(?i)^::1$`),

				// Unique local addresses (ULA) fc00::/7
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

				// Well-known public resolver / anycast service IPv6 (generally non-PII)
				regexp.MustCompile(`(?i)^2001:4860:4860::8888$`), // Google
				regexp.MustCompile(`(?i)^2001:4860:4860::8844$`), // Google
				regexp.MustCompile(`(?i)^2606:4700:4700::1111$`), // Cloudflare
				regexp.MustCompile(`(?i)^2606:4700:4700::1001$`), // Cloudflare
				regexp.MustCompile(`(?i)^2620:fe::fe$`),           // Quad9
				regexp.MustCompile(`(?i)^2620:fe::9$`),            // Quad9
				regexp.MustCompile(`(?i)^2620:119:35::35$`),       // OpenDNS
				regexp.MustCompile(`(?i)^2620:119:53::53$`),       // OpenDNS
			},
		},
	}

	// Representative candidates. These are diverse and should be verified via whois.
	truePositives := []string{
		"2001:db9::1",
		"2a01:4f8:10a:3b3::2",
		"2601:645:8000:abcd::123",
		"2a02:26f7:abcd:12::5",
		"2405:4802:123:abcd::7",
		"2804:14d:abcd::10",
		"2c0f:fda8:1234::9",
		"2a10:3781:5:30::dead:beef",
		"2406:da1c:1f00::42",
		"2600:1700:beef:1::42",
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
		"2001:4860:4860::8888",
		"2606:4700:4700::1111",
		"2620:fe::fe",
	}

	return validate(r, truePositives, falsePositives)
}