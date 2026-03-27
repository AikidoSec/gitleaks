package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

// PublicIP detects public IPv4 addresses (excludes private/reserved ranges via allowlist)
func PublicIP() *config.Rule {
	// Strict IPv4 octet (0-255)
	ipOctet := `(?:25[0-5]|2[0-4]\d|1?\d{1,2})`
	// Full IPv4 with optional CIDR suffix (/0 - /32)
	ipv4 := `\b(?:` + ipOctet + `\.){3}` + ipOctet + `(?:/(?:3[0-2]|[12]?\d))?\b`

	r := config.Rule{
		Description: "Public IPv4 address",
		RuleID:      "public-ip-address",
		Regex:       generateUniqueTokenRegex(ipv4, true),
		// No keywords so the rule runs globally; relying on allowlist to filter noise
		Keywords: nil,
		Tags:     []string{"ip", "ipv4", "infrastructure"},
		// Exclude private, loopback, link-local, CGNAT, test-nets, multicast/broadcast, and special ranges
		Allowlist: config.Allowlist{
			RegexTarget: "match",
			Regexes: []*regexp.Regexp{
				// RFC1918 private
				regexp.MustCompile(`^10\.`),
				regexp.MustCompile(`^172\.(?:1[6-9]|2\d|3[0-1])\.`),
				regexp.MustCompile(`^192\.168\.`),

				// Loopback and link-local
				regexp.MustCompile(`^127\.`),
				regexp.MustCompile(`^169\.254\.`),

				// Carrier-grade NAT 100.64.0.0/10
				regexp.MustCompile(`^100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.`),

				// Test/Documentation nets
				regexp.MustCompile(`^192\.0\.2\.`),    // TEST-NET-1
				regexp.MustCompile(`^198\.51\.100\.`), // TEST-NET-2
				regexp.MustCompile(`^203\.0\.113\.`),  // TEST-NET-3

				// Benchmarking / special-purpose
				regexp.MustCompile(`^198\.18\.`), // 198.18.0.0/15 (incl. 198.19.x.x)
				regexp.MustCompile(`^198\.19\.`),
				regexp.MustCompile(`^192\.0\.0\.`),

				// Multicast and reserved (224.0.0.0 – 255.255.255.255)
				regexp.MustCompile(`^(?:22[4-9]|23\d|24\d|25[0-5])\.`),

				// All zeros and broadcast special-cases
				regexp.MustCompile(`^0\.`),
				regexp.MustCompile(`^255\.255\.255\.255$`),
			},
		},
	}

	// Validate with representative examples (including CIDR)
	truePositives := []string{
		"93.184.216.34",
		"52.216.0.1",
		"73.54.201.89",
		"86.12.45.230",
		"14.201.88.19",
		"189.203.45.17",
		"41.190.23.8",
		"112.198.87.120",
		"201.17.45.200",
		"95.91.12.34",
		"213.87.141.66",
		"122.170.23.45",
		"101.204.83.101/32",
	}

	falsePositives := []string{
		"10.0.0.1",
		"172.16.0.10",
		"192.168.1.5",
		"127.0.0.1",
		"169.254.10.20",
		"100.64.1.2",
		"198.51.100.7",
		"203.0.113.99",
		"224.0.0.1",
		"255.255.255.255",
	}

	return validate(r, truePositives, falsePositives)
}