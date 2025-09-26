package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

// PublicKey detects public key material (PEM or SSH)
func PublicKey() *config.Rule {
	// PEM public key block (non-greedy content)
	pem := `-----BEGIN[ A-Z0-9_-]{0,100}PUBLIC KEY(?: BLOCK)?-----[\s\S]*?-----END[ A-Z0-9_-]{0,100}PUBLIC KEY(?: BLOCK)?-----`

	// SSH public keys (authorized_keys style)
	// Allow '.', '_' and '-' to accommodate placeholder examples and variations.
	ssh := `(?:ssh-(?:rsa|ed25519)|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/=._-]{20,}`

	// Case-insensitive, no leading word-boundary; include a reasonable trailing terminator
	regex := `(?i)(?:` + pem + `|` + ssh + `)(?:['"\s\x60;]|$)`

	r := config.Rule{
		Description: "Public key material (PEM or SSH)",
		RuleID:      "public-key",
		Regex:       regexp.MustCompile(regex),
		Keywords:    []string{"-----BEGIN", "ssh-", "ecdsa-sha2-nistp"},
		Tags:        []string{"key", "public-key", "crypto"},
	}

	// Validate
	truePositives := []string{
		`-----BEGIN PUBLIC KEY-----
MIIBIjANBg...AB
-----END PUBLIC KEY-----`,
		`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCexampleBase64Here moreBase64... user@host`,
		`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexampleBase64... user@host`,
		`ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdH... comment`,
	}
	return validate(r, truePositives, nil)
}