package config

import (
	"fmt"
	"sort"
	"testing"

	regexp "github.com/wasilibs/go-re2"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const configPath = "../testdata/config/"

type allowlistSnapshot struct {
	Description string
	RegexTarget string
	Regexes     []string
	Paths       []string
	Commits     []string
	StopWords   []string
}

type ruleSnapshot struct {
	Description string
	RuleID      string
	Entropy     float64
	SecretGroup int
	Regex       string
	Path        string
	Tags        []string
	Keywords    []string
	Allowlist   allowlistSnapshot
}

func snapshotRegexp(re *regexp.Regexp) string {
	if re == nil {
		return ""
	}
	return re.String()
}

func snapshotRegexps(res []*regexp.Regexp) []string {
	if len(res) == 0 {
		return nil
	}
	out := make([]string, 0, len(res))
	for _, re := range res {
		out = append(out, snapshotRegexp(re))
	}
	return out
}

func snapshotRules(rules map[string]Rule) map[string]ruleSnapshot {
	if rules == nil {
		return nil
	}
	out := make(map[string]ruleSnapshot, len(rules))
	for id, r := range rules {
		rs := ruleSnapshot{
			Description: r.Description,
			RuleID:      r.RuleID,
			Entropy:     r.Entropy,
			SecretGroup: r.SecretGroup,
			Regex:       snapshotRegexp(r.Regex),
			Path:        snapshotRegexp(r.Path),
			Tags:        r.Tags,
			Keywords:    r.Keywords,
			Allowlist: allowlistSnapshot{
				Description: r.Allowlist.Description,
				RegexTarget: r.Allowlist.RegexTarget,
				Regexes:     snapshotRegexps(r.Allowlist.Regexes),
				Paths:       snapshotRegexps(r.Allowlist.Paths),
				Commits:     r.Allowlist.Commits,
				StopWords:   r.Allowlist.StopWords,
			},
		}
		// Make slice comparisons stable even if upstream order changes.
		sort.Strings(rs.Allowlist.Regexes)
		sort.Strings(rs.Allowlist.Paths)
		out[id] = rs
	}
	return out
}

func TestTranslate(t *testing.T) {
	tests := []struct {
		cfgName   string
		cfg       Config
		wantError error
	}{
		{
			cfgName: "allow_aws_re",
			cfg: Config{
				Rules: map[string]Rule{"aws-access-key": {
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Tags:        []string{"key", "AWS"},
					Keywords:    []string{},
					RuleID:      "aws-access-key",
					Allowlist: Allowlist{
						Regexes: []*regexp.Regexp{
							regexp.MustCompile("AKIALALEMEL33243OLIA"),
						},
					},
				},
				},
			},
		},
		{
			cfgName: "allow_commit",
			cfg: Config{
				Rules: map[string]Rule{"aws-access-key": {
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Tags:        []string{"key", "AWS"},
					Keywords:    []string{},
					RuleID:      "aws-access-key",
					Allowlist: Allowlist{
						Commits: []string{"allowthiscommit"},
					},
				},
				},
			},
		},
		{
			cfgName: "allow_path",
			cfg: Config{
				Rules: map[string]Rule{"aws-access-key": {
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Tags:        []string{"key", "AWS"},
					Keywords:    []string{},
					RuleID:      "aws-access-key",
					Allowlist: Allowlist{
						Paths: []*regexp.Regexp{
							regexp.MustCompile(".go"),
						},
					},
				},
				},
			},
		},
		{
			cfgName: "entropy_group",
			cfg: Config{
				Rules: map[string]Rule{"discord-api-key": {
					Description: "Discord API key",
					Regex:       regexp.MustCompile(`(?i)(discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{64})['\"]`),
					RuleID:      "discord-api-key",
					Allowlist:   Allowlist{},
					Entropy:     3.5,
					SecretGroup: 3,
					Tags:        []string{},
					Keywords:    []string{},
				},
				},
			},
		},
		{
			cfgName:   "bad_entropy_group",
			cfg:       Config{},
			wantError: fmt.Errorf("Discord API key invalid regex secret group 5, max regex secret group 3"),
		},
		{
			cfgName: "base",
			cfg: Config{
				Rules: map[string]Rule{
					"aws-access-key": {
						Description: "AWS Access Key",
						Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
						Tags:        []string{"key", "AWS"},
						Keywords:    []string{},
						RuleID:      "aws-access-key",
					},
					"aws-secret-key": {
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Tags:        []string{"key", "AWS"},
						Keywords:    []string{},
						RuleID:      "aws-secret-key",
					},
					"aws-secret-key-again": {
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Tags:        []string{"key", "AWS"},
						Keywords:    []string{},
						RuleID:      "aws-secret-key-again",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		viper.Reset()
		viper.AddConfigPath(configPath)
		viper.SetConfigName(tt.cfgName)
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		require.NoError(t, err)

		var vc ViperConfig
		err = viper.Unmarshal(&vc)
		require.NoError(t, err)
		cfg, err := vc.Translate()
		assert.Equal(t, tt.wantError, err)
		assert.Equal(t, snapshotRules(tt.cfg.Rules), snapshotRules(cfg.Rules))
	}
}
