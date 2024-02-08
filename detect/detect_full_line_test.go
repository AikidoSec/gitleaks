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
					StartLine:   8,
					EndLine:     8,
					StartColumn: 15,
					EndColumn:   34,
					Line:        "        <YEAR>AKIAJWY75QGOEOC2J5GA</YEAR>",
					FullLine:    "<YEAR>AKIAJWY75QGOEOC2J5GA</YEAR>",
					Match:       "AKIAJWY75QGOEOC2J5GA",
					Secret:      "AKIAJWY75QGOEOC2J5GA",
					File:        "test.xml",
					SymlinkFile: "",
					Commit:      "a422992fa845ddabb3044fe94f9c7dc816fefd15",
					Entropy:     3.6841838,
					Author:      "Kemosabert",
					Email:       "bert.coppens14@gmail.com",
					Date:        "2024-02-08T09:26:03Z",
					Message:     "inject secret",
					RuleID:      "aws-access-key",
					Fingerprint: "a422992fa845ddabb3044fe94f9c7dc816fefd15:test.xml:aws-access-key:8",
					Tags:        []string{"key", "AWS"},
				},
				{
					Description: "Github Personal Access Token",
					StartLine:   1,
					EndLine:     1,
					StartColumn: 1019,
					EndColumn:   1058,
					Line:        "<CATALOG><CD><TITLE>Empire Burlesque</TITLE><ARTIST>Bob Dylan</ARTIST><COUNTRY>USA</COUNTRY><COMPANY>Columbia</COMPANY>z<PRICE>10.90</PRICE><YEAR>2000</YEAR></CD><CD><TITLE>Hide your heart</TITLE><ARTIST>Bonnie Tyler</ARTIST><COUNTRY>UK</COUNTRY><COMPANY>CBS Records</COMPANY><PRICE>9.90</PRICE><YEAR>1988</YEAR></CD><CD><TITLE>Greatest Hits</TITLE><ARTIST> Dolly Parton</ARTIST><COUNTRY>USA</COUNTRY><COMPANY>RCA</COMPANY><PRICE>9.90</PRICE><YEAR>1982</YEAR></CD><CD><TITLE>Still got the blues</TITLE><ARTIST>Gary Moore</ARTIST><COUNTRY>UK</COUNTRY><COMPANY>Virgin records</COMPANY><PRICE>10.20</PRICE><YEAR>1990</YEAR></CD><CD><TITLE>Eros</TITLE><ARTIST>Eros Ramazzotti</ARTIST><COUNTRY>EU</COUNTRY><COMPANY>BMG</COMPANY><PRICE>9.90</PRICE><YEAR>1997</YEAR></CD><CD><TITLE>One night only</TITLE><ARTIST>Bee Gees</ARTIST><COUNTRY>UK</COUNTRY><COMPANY>Polydor</COMPANY><PRICE>10.90</PRICE><YEAR>1998</YEAR></CD><CD><TITLE>Sylvias Mother</TITLE><ARTIST>Dr.Hook</ARTIST><COUNTRY>UK</COUNTRY><COMPANY>CBS</COMPANY><PRICE>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</PRICE><YEAR>1973</YEAR></CD><CD><TITLE>Maggie May</TITLE><ARTIST>Rod Stewart</ARTIST><COUNTRY>UK</COUNTRY><COMPANY>Pickwick</COMPANY><PRICE>8.50</PRICE><YEAR>1990</YEAR></CD><CD><TITLE>Romanza</TITLE><ARTIST>Andrea Bocelli</ARTIST><COUNTRY>EU</COUNTRY><COMPANY>Polydor</COMPANY><PRICE>10.80</PRICE><YEAR>1996</YEAR></CD><CD><TITLE>When a man loves a woman</TITLE><ARTIST>Percy Sledge</ARTIST><COUNTRY>USA</COUNTRY><COMPANY>Atlantic</COMPANY><PRICE>8.70</PRICE><YEAR>1987</YEAR></CD><CD><TITLE>Black angel</TITLE><ARTIST>Savage Rose</ARTIST><COUNTRY>EU</COUNTRY><COMPANY>Mega</COMPANY><PRICE>10.90</PRICE><YEAR>1995</YEAR></CD></CATALOG>",
					FullLine:    "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",
					Match:       "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",
					Secret:      "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",
					File:        "longfile.txt",
					SymlinkFile: "",
					Commit:      "f181f98031ded3e9fe1b01a057ee0b657152ff9e",
					Entropy:     4.8341837,
					Author:      "Kemosabert",
					Email:       "bert.coppens14@gmail.com",
					Date:        "2024-02-08T09:37:27Z",
					Message:     "add le token",
					RuleID:      "github-pat",
					Fingerprint: "f181f98031ded3e9fe1b01a057ee0b657152ff9e:longfile.txt:github-pat:1",
					Tags:        []string{"key", "Github"},
				},
				{
					Description: "Github Personal Access Token",
					StartLine:   19,
					EndLine:     19,
					StartColumn: 79,
					EndColumn:   118,
					Line:        "          image: europe-docker.pkg.dev/qover-platform/cr/operators/authgoogle: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",
					FullLine:    "image: europe-docker.pkg.dev/qover-platform/cr/operators/authgoogle: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",
					Match:       "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",
					Secret:      "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",
					File:        "deployment.yaml",
					SymlinkFile: "",
					Commit:      "b03f41c505380c4c70f3a8309b85c880271f4f1f",
					Entropy:     4.8341837,
					Author:      "Kemosabert",
					Email:       "bert.coppens14@gmail.com",
					Date:        "2024-02-08T09:45:49Z",
					Message:     "increase build",
					RuleID:      "github-pat",
					Fingerprint: "b03f41c505380c4c70f3a8309b85c880271f4f1f:deployment.yaml:github-pat:19",
					Tags:        []string{"key", "Github"},
				},
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
