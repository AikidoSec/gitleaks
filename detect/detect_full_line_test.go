package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// var configPath = "../testdata/config/"
// const repoBasePath = "../testdata/repos/"

// const fixturesBasePath = "../testdata/full_line"

func TestDetectWithFullLine(t *testing.T) {
	tests := []struct {
		cfgName          string
		source           string
		logOpts          string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "full_line"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					Secret:      "AKIALALEMEL33243OLIA",
					Match:       "AKIALALEMEL33243OLIA",
					Line:        "\n        <TOKEN>AKIALALEMEL33243OLIA</TOKEN>",
					FullLine:    `<TOKEN>AKIALALEMEL33243OLIA</TOKEN>`,
					File:        "test.xml",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					StartLine:   185,
					EndLine:     185,
					StartColumn: 17,
					EndColumn:   36,
					Entropy:     3.0841837,
					Commit:      "e654f5bf0f10926b828ccf8f07b5b2f49fd0a179",
					Author:      "Kemosabert",
					Email:       "bert.coppens14@gmail.com",
					Date:        "2024-02-08T09:09:55Z",
					Message:     "add test file",
					Fingerprint: "e654f5bf0f10926b828ccf8f07b5b2f49fd0a179:test.xml:aws-access-key:185",
				},
				{
					Description: "AWS Access Key",
					Secret:      "AKIAJWY75QGOEOC2J5GA",
					Match:       "AKIAJWY75QGOEOC2J5GA",
					Line:        "\n        <TITLE>AKIAJWY75QGOEOC2J5GA</TITLE>",
					FullLine:    `<TITLE>AKIAJWY75QGOEOC2J5GA</TITLE>`,
					File:        "test.xml",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					StartLine:   204,
					EndLine:     204,
					StartColumn: 17,
					EndColumn:   36,
					Entropy:     3.6841838,
					Commit:      "e654f5bf0f10926b828ccf8f07b5b2f49fd0a179",
					Author:      "Kemosabert",
					Email:       "bert.coppens14@gmail.com",
					Date:        "2024-02-08T09:09:55Z",
					Message:     "add test file",
					Fingerprint: "e654f5bf0f10926b828ccf8f07b5b2f49fd0a179:test.xml:aws-access-key:204",
				},
			},
		},
	}

	moveDotGit(t, "dotGit", ".git")
	defer moveDotGit(t, ".git", "dotGit")

	for _, tt := range tests {

		viper.AddConfigPath(configPath)
		viper.SetConfigName("simple")
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		require.NoError(t, err)

		var vc config.ViperConfig
		err = viper.Unmarshal(&vc)
		require.NoError(t, err)
		cfg, err := vc.Translate()
		require.NoError(t, err)
		detector := NewDetector(cfg)

		var ignorePath string
		info, err := os.Stat(tt.source)
		require.NoError(t, err)

		if info.IsDir() {
			ignorePath = filepath.Join(tt.source, ".gitleaksignore")
		} else {
			ignorePath = filepath.Join(filepath.Dir(tt.source), ".gitleaksignore")
		}
		err = detector.AddGitleaksIgnore(ignorePath)
		require.NoError(t, err)

		gitCmd, err := sources.NewGitLogCmd(tt.source, tt.logOpts)
		require.NoError(t, err)
		findings, err := detector.DetectGit(gitCmd)
		fmt.Printf("%+v", err)
		require.NoError(t, err)

		for _, f := range findings {
			f.Match = "" // remove lines cause copying and pasting them has some wack formatting
		}
		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}
