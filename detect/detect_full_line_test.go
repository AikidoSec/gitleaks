package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

// var configPath = "../testdata/config/"
// const repoBasePath = "../testdata/repos/"

const fixturesBasePath = "../testdata/full_line"

func TestDetectWithFullLine(t *testing.T) {
	tests := []struct {
		cfgName      string
		baselinePath string
		fixture      string
		// NOTE: for expected findings, all line numbers will be 0
		// because line deltas are added _after_ the finding is created.
		// I.e., if the finding is from a --no-git file, the line number will be
		// increase by 1 in DetectFromFiles(). If the finding is from git,
		// the line number will be increased by the patch delta.
		expectedFindings []report.Finding
		wantError        error
	}{
		{
			cfgName: "simple",
			fixture: "test.xml",
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					Secret:      "AKIALALEMEL33243OLIA",
					Match:       "AKIALALEMEL33243OLIA",
					Line:        "\n        <TOKEN>AKIALALEMEL33243OLIA</TOKEN>",
					FullLine:    `<TOKEN>AKIALALEMEL33243OLIA</TOKEN>`,
					File:        "tmp.go",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					StartLine:   184,
					EndLine:     184,
					StartColumn: 17,
					EndColumn:   36,
					Entropy:     3.0841837,
				},
				{
					Description: "AWS Access Key",
					Secret:      "AKIAJWY75QGOEOC2J5GA",
					Match:       "AKIAJWY75QGOEOC2J5GA",
					Line:        "\n        <TITLE>AKIAJWY75QGOEOC2J5GA</TITLE>",
					FullLine:    `<TITLE>AKIAJWY75QGOEOC2J5GA</TITLE>`,
					File:        "tmp.go",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					StartLine:   203,
					EndLine:     203,
					StartColumn: 17,
					EndColumn:   36,
					Entropy:     3.6841838,
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

		var vc config.ViperConfig
		err = viper.Unmarshal(&vc)
		require.NoError(t, err)
		cfg, err := vc.Translate()
		cfg.Path = filepath.Join(configPath, tt.cfgName+".toml")
		assert.Equal(t, tt.wantError, err)
		d := NewDetector(cfg)
		d.baselinePath = tt.baselinePath

		data, err := os.ReadFile(filepath.Join(fixturesBasePath, tt.fixture))
		assert.Nil(t, err)

		fragment := Fragment{Raw: string(data), FilePath: "tmp.go"}

		findings := d.Detect(fragment)
		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}
