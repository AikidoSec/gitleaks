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

const configPath = "../testdata/config/"
const repoBasePath = "../testdata/repos/"

func TestDetect(t *testing.T) {
	tests := []struct {
		cfgName      string
		baselinePath string
		fragment     Fragment
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
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OKIA\ // gitleaks:allow"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw: `awsToken := \

		        \"AKIALALEMEL33243OKIA\ // gitleaks:allow"

		        `,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw: `awsToken := \"AKIALALEMEL33243OKIA\"

		                // gitleaks:allow"

		                `,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					Secret:      "AKIALALEMEL33243OKIA",
					Match:       "AKIALALEMEL33243OKIA",
					File:        "tmp.go",
					Line:        `awsToken := \"AKIALALEMEL33243OKIA\"`,
					FullLine:    `awsToken := \"AKIALALEMEL33243OKIA\"`,
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					StartLine:   0,
					EndLine:     0,
					StartColumn: 15,
					EndColumn:   34,
					Entropy:     3.1464393,
				},
			},
		},
		{
			cfgName: "escaped_character_group",
			fragment: Fragment{
				Raw:      `pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					Description: "PyPI upload token",
					Secret:      "pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB",
					Match:       "pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB",
					Line:        `pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB`,
					FullLine:    `pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB`,
					File:        "tmp.go",
					RuleID:      "pypi-upload-token",
					Tags:        []string{"key", "pypi"},
					StartLine:   0,
					EndLine:     0,
					StartColumn: 1,
					EndColumn:   86,
					Entropy:     1.9606875,
				},
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					Secret:      "AKIALALEMEL33243OLIA",
					Match:       "AKIALALEMEL33243OLIA",
					Line:        `awsToken := \"AKIALALEMEL33243OLIA\"`,
					FullLine:    `awsToken := \"AKIALALEMEL33243OLIA\"`,
					File:        "tmp.go",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					StartLine:   0,
					EndLine:     0,
					StartColumn: 15,
					EndColumn:   34,
					Entropy:     3.0841837,
				},
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw: `
					<CATALOG>
						<CD>
							<TITLE>Empire Burlesque</TITLE>
							<ARTIST>Bob Dylan</ARTIST>
							<COUNTRY>USA</COUNTRY>
							<COMPANY>Columbia</COMPANY>
							<PRICE>10.90</PRICE>
							<YEAR>1985</YEAR>
						</CD>
						<CD>
							<TITLE>Hide your heart</TITLE>
							<ARTIST>Bonnie Tyler</ARTIST>
							<COUNTRY>UK</COUNTRY>
							<COMPANY>CBS Records</COMPANY>
							<PRICE>9.90</PRICE>
							<YEAR>1988</YEAR>
						</CD>
						<CD>
							<TITLE>Greatest Hits</TITLE>
							<ARTIST>Dolly Parton</ARTIST>
							<COUNTRY>USA</COUNTRY>
							<COMPANY>RCA</COMPANY>
							<PRICE>9.90</PRICE>
							<YEAR>1982</YEAR>
						</CD>
						<CD>
							<TITLE>Still got the blues</TITLE>
							<ARTIST>Gary Moore</ARTIST>
							<COUNTRY>UK</COUNTRY>
							<COMPANY>Virgin records</COMPANY>
							<PRICE>10.20</PRICE>
							<YEAR>1990</YEAR>
						</CD>
						<CD>
							<TITLE>Eros</TITLE>
							<ARTIST>Eros Ramazzotti</ARTIST>
							<COUNTRY>EU</COUNTRY>
							<COMPANY>BMG</COMPANY>
							<PRICE>9.90</PRICE>
							<YEAR>1997</YEAR>
						</CD>
						<CD>
							<TITLE>One night only</TITLE>
							<ARTIST>Bee Gees</ARTIST>
							<COUNTRY>UK</COUNTRY>
							<COMPANY>Polydor</COMPANY>
							<PRICE>10.90</PRICE>
							<YEAR>1998</YEAR>
						</CD>
						<CD>
							<TITLE>Sylvias Mother</TITLE>
							<ARTIST>Dr.Hook</ARTIST>
							<COUNTRY>UK</COUNTRY>
							<COMPANY>CBS</COMPANY>
							<PRICE>8.10</PRICE>
							<YEAR>1973</YEAR>
						</CD>
						<CD>
							<TITLE>Maggie May</TITLE>
							<ARTIST>Rod Stewart</ARTIST>
							<COUNTRY>UK</COUNTRY>
							<COMPANY>Pickwick</COMPANY>
							<PRICE>8.50</PRICE>
							<YEAR>1990</YEAR>
						</CD>
						<CD>
							<TITLE>Romanza</TITLE>
							<ARTIST>Andrea Bocelli</ARTIST>
							<COUNTRY>EU</COUNTRY>
							<COMPANY>Polydor</COMPANY>
							<PRICE>10.80</PRICE>
							<YEAR>1996</YEAR>
						</CD>
						<CD>
							<TITLE>When a man loves a woman</TITLE>
							<ARTIST>Percy Sledge</ARTIST>
							<COUNTRY>USA</COUNTRY>
							<COMPANY>Atlantic</COMPANY>
							<PRICE>8.70</PRICE>
							<YEAR>1987</YEAR>
						</CD>
						<CD>
							<TITLE>Black angel</TITLE>
							<ARTIST>Savage Rose</ARTIST>
							<COUNTRY>EU</COUNTRY>
							<COMPANY>Mega</COMPANY>
							<PRICE>10.90</PRICE>
							<YEAR>1995</YEAR>
						</CD>
						<CD>
							<TITLE>1999 Grammy Nominees</TITLE>
							<ARTIST>Many</ARTIST>
							<COUNTRY>USA</COUNTRY>
							<COMPANY>Grammy</COMPANY>
							<PRICE>10.20</PRICE>
							<YEAR>1999</YEAR>
						</CD>
						<CD>
							<TITLE>For the good times</TITLE>
							<ARTIST>Kenny Rogers</ARTIST>
							<COUNTRY>UK</COUNTRY>
							<COMPANY>Mucik Master</COMPANY>
							<PRICE>8.70</PRICE>
							<YEAR>1995</YEAR>
						</CD>
						<CD>
							<TITLE>Big Willie style</TITLE>
							<ARTIST>Will Smith</ARTIST>
							<COUNTRY>USA</COUNTRY>
							<COMPANY>Columbia</COMPANY>
							<PRICE>9.90</PRICE>
							<YEAR>1997</YEAR>
						</CD>
						<CD>
							<TITLE>Tupelo Honey</TITLE>
							<ARTIST>Van Morrison</ARTIST>
							<COUNTRY>UK</COUNTRY>
							<COMPANY>Polydor</COMPANY>
							<PRICE>8.20</PRICE>
							<YEAR>1971</YEAR>
						</CD>
						<CD>
							<TITLE>Soulsville</TITLE>
							<ARTIST>Jorn Hoel</ARTIST>
							<COUNTRY>Norway</COUNTRY>
							<COMPANY>WEA</COMPANY>
							<PRICE>7.90</PRICE>
							<YEAR>1996</YEAR>
						</CD>
						<CD>
							<TITLE>The very best of</TITLE>
							<ARTIST>Cat Stevens</ARTIST>
							<COUNTRY>UK</COUNTRY>
							<COMPANY>Island</COMPANY>
							<PRICE>8.90</PRICE>
							<YEAR>1990</YEAR>
						</CD>
						<CD>
							<TITLE>Stop</TITLE>
							<ARTIST>Sam Brown</ARTIST>
							<COUNTRY>UK</COUNTRY>
							<COMPANY>A and M</COMPANY>
							<PRICE>8.90</PRICE>
							<YEAR>1988</YEAR>
						</CD>
						<CD>
							<TITLE>Bridge of Spies</TITLE>
							<ARTIST>T'Pau</ARTIST>
							<COUNTRY>UK</COUNTRY>
							<COMPANY>Siren</COMPANY>
							<PRICE>7.90</PRICE>
							<YEAR>1987</YEAR>
						</CD>
						<CD>
							<TITLE>Private Dancer</TITLE>
							<ARTIST>Tina Turner</ARTIST>
							<COUNTRY>UK</COUNTRY>
							<COMPANY>Capitol</COMPANY>
							<PRICE>8.90</PRICE>
							<YEAR>1983</YEAR>
						</CD>
						<CD>
							<TITLE>Midt om natten</TITLE>
							<ARTIST>Kim Larsen</ARTIST>
							<COUNTRY>EU</COUNTRY>
							<COMPANY>Medley</COMPANY>
							<PRICE>7.80</PRICE>
							<YEAR>1983</YEAR>
						</CD>
						<CD>
							<TITLE>Pavarotti Gala Concert</TITLE>
							<ARTIST>Luciano Pavarotti</ARTIST>
							<COUNTRY>UK</COUNTRY>
							<COMPANY>DECCA</COMPANY>
							<PRICE>9.90</PRICE>
							<YEAR>1991</YEAR>
						</CD>
						<CD>
							<TITLE>The dock of the bay</TITLE>
							<ARTIST>Otis Redding</ARTIST>
							<COUNTRY>USA</COUNTRY>
							<COMPANY>Stax Records</COMPANY>
							<PRICE>7.90</PRICE>
							<YEAR>1968</YEAR>
							<TOKEN>AKIALALEMEL33243OLIA</TOKEN>
						</CD>
						<CD>
							<TITLE>Picture book</TITLE>
							<ARTIST>Simply Red</ARTIST>
							<COUNTRY>EU</COUNTRY>
							<COMPANY>Elektra</COMPANY>
							<PRICE>7.20</PRICE>
							<YEAR>1985</YEAR>
						</CD>
						<CD>
							<TITLE>Red</TITLE>
							<ARTIST>The Communards</ARTIST>
							<COUNTRY>UK</COUNTRY>
							<COMPANY>London</COMPANY>
							<PRICE>7.80</PRICE>
							<YEAR>1987</YEAR>
						</CD>
						<CD>
							<TITLE>AKIAJWY75QGOEOC2J5GA</TITLE>
							<ARTIST>Joe Cocker</ARTIST>
							<COUNTRY>USA</COUNTRY>
							<COMPANY>EMI</COMPANY>
							<PRICE>8.20</PRICE>
							<YEAR>1987</YEAR>
						</CD>
					</CATALOG>
				`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					Secret:      "AKIALALEMEL33243OLIA",
					Match:       "AKIALALEMEL33243OLIA",
					Line:        "\n\t\t\t\t\t\t\t<TOKEN>AKIALALEMEL33243OLIA</TOKEN>",
					FullLine:    `<TOKEN>AKIALALEMEL33243OLIA</TOKEN>`,
					File:        "tmp.go",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					StartLine:   185,
					EndLine:     185,
					StartColumn: 16,
					EndColumn:   35,
					Entropy:     3.0841837,
				},
				{
					Description: "AWS Access Key",
					Secret:      "AKIAJWY75QGOEOC2J5GA",
					Match:       "AKIAJWY75QGOEOC2J5GA",
					Line:        "\n\t\t\t\t\t\t\t<TITLE>AKIAJWY75QGOEOC2J5GA</TITLE>",
					FullLine:    `<TITLE>AKIAJWY75QGOEOC2J5GA</TITLE>`,
					File:        "tmp.go",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					StartLine:   204,
					EndLine:     204,
					StartColumn: 16,
					EndColumn:   35,
					Entropy:     3.6841838,
				},
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;`,
				FilePath: "tmp.sh",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Sidekiq Secret",
					Match:       "BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;",
					Secret:      "cafebabe:deadbeef",
					Line:        `export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;`,
					FullLine:    `export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;`,
					File:        "tmp.sh",
					RuleID:      "sidekiq-secret",
					Tags:        []string{},
					Entropy:     2.6098502,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 8,
					EndColumn:   60,
				},
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `echo hello1; export BUNDLE_ENTERPRISE__CONTRIBSYS__COM="cafebabe:deadbeef" && echo hello2`,
				FilePath: "tmp.sh",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Sidekiq Secret",
					Match:       "BUNDLE_ENTERPRISE__CONTRIBSYS__COM=\"cafebabe:deadbeef\"",
					Secret:      "cafebabe:deadbeef",
					File:        "tmp.sh",
					Line:        `echo hello1; export BUNDLE_ENTERPRISE__CONTRIBSYS__COM="cafebabe:deadbeef" && echo hello2`,
					FullLine:    `echo hello1; export BUNDLE_ENTERPRISE__CONTRIBSYS__COM="cafebabe:deadbeef" && echo hello2`,
					RuleID:      "sidekiq-secret",
					Tags:        []string{},
					Entropy:     2.6098502,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 21,
					EndColumn:   74,
				},
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `url = "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1"`,
				FilePath: "tmp.sh",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Sidekiq Sensitive URL",
					Match:       "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:",
					Secret:      "cafeb4b3:d3adb33f",
					File:        "tmp.sh",
					Line:        `url = "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1"`,
					FullLine:    `url = "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1"`,
					RuleID:      "sidekiq-sensitive-url",
					Tags:        []string{},
					Entropy:     2.984234,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 8,
					EndColumn:   58,
				},
			},
		},
		{
			cfgName: "allow_aws_re",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "allow_path",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "allow_commit",
			fragment: Fragment{
				Raw:       `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath:  "tmp.go",
				CommitSHA: "allowthiscommit",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "entropy_group",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Discord API key",
					Match:       "Discord_Public_Key = \"e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5\"",
					Secret:      "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5",
					Line:        `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
					FullLine:    `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
					File:        "tmp.go",
					RuleID:      "discord-api-key",
					Tags:        []string{},
					Entropy:     3.7906237,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 7,
					EndColumn:   93,
				},
			},
		},
		{
			cfgName: "generic_with_py_path",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "generic_with_py_path",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.py",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Generic API Key",
					Match:       "Key = \"e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5\"",
					Secret:      "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5",
					Line:        `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
					FullLine:    `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
					File:        "tmp.py",
					RuleID:      "generic-api-key",
					Tags:        []string{},
					Entropy:     3.7906237,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 22,
					EndColumn:   93,
				},
			},
		},
		{
			cfgName: "path_only",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.py",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Python Files",
					Match:       "file detected: tmp.py",
					File:        "tmp.py",
					RuleID:      "python-files-only",
					Tags:        []string{},
				},
			},
		},
		{
			cfgName: "bad_entropy_group",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
			wantError:        fmt.Errorf("Discord API key invalid regex secret group 5, max regex secret group 3"),
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: filepath.Join(configPath, "simple.toml"),
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "allow_global_aws_re",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "generic_with_py_path",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "load2523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.py",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName:      "path_only",
			baselinePath: ".baseline.json",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: ".baseline.json",
			},
			expectedFindings: []report.Finding{},
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

		findings := d.Detect(tt.fragment)
		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}

// TestFromGit tests the FromGit function
func TestFromGit(t *testing.T) {
	tests := []struct {
		cfgName          string
		source           string
		logOpts          string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "small"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 19,
					EndColumn:   38,
					Line:        "\n    awsToken := \"AKIALALEMEL33243OLIA\"",
					FullLine:    `awsToken := "AKIALALEMEL33243OLIA"`,
					Secret:      "AKIALALEMEL33243OLIA",
					Match:       "AKIALALEMEL33243OLIA",
					File:        "main.go",
					Date:        "2021-11-02T23:37:53Z",
					Commit:      "1b6da43b82b22e4eaa10bcf8ee591e91abbfc587",
					Author:      "Zachary Rice",
					Email:       "zricer@protonmail.com",
					Message:     "Accidentally add a secret",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "1b6da43b82b22e4eaa10bcf8ee591e91abbfc587:main.go:aws-access-key:20",
				},
				{
					Description: "AWS Access Key",
					StartLine:   9,
					EndLine:     9,
					StartColumn: 17,
					EndColumn:   36,
					Secret:      "AKIALALEMEL33243OLIA",
					Match:       "AKIALALEMEL33243OLIA",
					Line:        "\n\taws_token := \"AKIALALEMEL33243OLIA\"",
					FullLine:    `aws_token := "AKIALALEMEL33243OLIA"`,
					File:        "foo/foo.go",
					Date:        "2021-11-02T23:48:06Z",
					Commit:      "491504d5a31946ce75e22554cc34203d8e5ff3ca",
					Author:      "Zach Rice",
					Email:       "zricer@protonmail.com",
					Message:     "adding foo package with secret",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "491504d5a31946ce75e22554cc34203d8e5ff3ca:foo/foo.go:aws-access-key:9",
				},
			},
		},
		{
			source:  filepath.Join(repoBasePath, "small"),
			logOpts: "--all foo...",
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					StartLine:   9,
					EndLine:     9,
					StartColumn: 17,
					EndColumn:   36,
					Secret:      "AKIALALEMEL33243OLIA",
					Line:        "\n\taws_token := \"AKIALALEMEL33243OLIA\"",
					FullLine:    `aws_token := "AKIALALEMEL33243OLIA"`,
					Match:       "AKIALALEMEL33243OLIA",
					Date:        "2021-11-02T23:48:06Z",
					File:        "foo/foo.go",
					Commit:      "491504d5a31946ce75e22554cc34203d8e5ff3ca",
					Author:      "Zach Rice",
					Email:       "zricer@protonmail.com",
					Message:     "adding foo package with secret",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "491504d5a31946ce75e22554cc34203d8e5ff3ca:foo/foo.go:aws-access-key:9",
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
func TestFromGitStaged(t *testing.T) {
	tests := []struct {
		cfgName          string
		source           string
		logOpts          string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "staged"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					StartLine:   7,
					EndLine:     7,
					StartColumn: 18,
					EndColumn:   37,
					Line:        "\n\taws_token2 := \"AKIALALEMEL33243OLIA\" // this one is not",
					FullLine:    `aws_token2 := "AKIALALEMEL33243OLIA" // this one is not`,
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "api/api.go",
					SymlinkFile: "",
					Commit:      "",
					Entropy:     3.0841837,
					Author:      "",
					Email:       "",
					Date:        "0001-01-01T00:00:00Z",
					Message:     "",
					Tags: []string{
						"key",
						"AWS",
					},
					RuleID:      "aws-access-key",
					Fingerprint: "api/api.go:aws-access-key:7",
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
		err = detector.AddGitleaksIgnore(filepath.Join(tt.source, ".gitleaksignore"))
		require.NoError(t, err)
		gitCmd, err := sources.NewGitDiffCmd(tt.source, true)
		require.NoError(t, err)
		findings, err := detector.DetectGit(gitCmd)
		require.NoError(t, err)

		for _, f := range findings {
			f.Match = "" // remove lines cause copying and pasting them has some wack formatting
		}
		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}

// TestFromFiles tests the FromFiles function
func TestFromFiles(t *testing.T) {
	tests := []struct {
		cfgName          string
		source           string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "nogit"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					FullLine:    `awsToken := "AKIALALEMEL33243OLIA"`,
					File:        "../testdata/repos/nogit/main.go",
					SymlinkFile: "",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/repos/nogit/main.go:aws-access-key:20",
				},
			},
		},
		{
			source:  filepath.Join(repoBasePath, "nogit", "main.go"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					FullLine:    `awsToken := "AKIALALEMEL33243OLIA"`,
					File:        "../testdata/repos/nogit/main.go",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/repos/nogit/main.go:aws-access-key:20",
				},
			},
		},
		{
			source:           filepath.Join(repoBasePath, "nogit", "api.go"),
			cfgName:          "simple",
			expectedFindings: []report.Finding{},
		},
	}

	for _, tt := range tests {
		viper.AddConfigPath(configPath)
		viper.SetConfigName("simple")
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		require.NoError(t, err)

		var vc config.ViperConfig
		err = viper.Unmarshal(&vc)
		require.NoError(t, err)
		cfg, _ := vc.Translate()
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
		detector.FollowSymlinks = true
		paths, err := sources.DirectoryTargets(tt.source, detector.Sema, true)
		require.NoError(t, err)
		findings, err := detector.DetectFiles(paths)
		require.NoError(t, err)
		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}

func TestDetectWithSymlinks(t *testing.T) {
	tests := []struct {
		cfgName          string
		source           string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "symlinks/file_symlink"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					Description: "Asymmetric Private Key",
					StartLine:   1,
					EndLine:     1,
					StartColumn: 1,
					EndColumn:   35,
					Match:       "-----BEGIN OPENSSH PRIVATE KEY-----",
					Secret:      "-----BEGIN OPENSSH PRIVATE KEY-----",
					Line:        "-----BEGIN OPENSSH PRIVATE KEY-----",
					FullLine:    "-----BEGIN OPENSSH PRIVATE KEY-----",
					File:        "../testdata/repos/symlinks/source_file/id_ed25519",
					SymlinkFile: "../testdata/repos/symlinks/file_symlink/symlinked_id_ed25519",
					RuleID:      "apkey",
					Tags:        []string{"key", "AsymmetricPrivateKey"},
					Entropy:     3.587164,
					Fingerprint: "../testdata/repos/symlinks/source_file/id_ed25519:apkey:1",
				},
			},
		},
	}

	for _, tt := range tests {
		viper.AddConfigPath(configPath)
		viper.SetConfigName("simple")
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		require.NoError(t, err)

		var vc config.ViperConfig
		err = viper.Unmarshal(&vc)
		require.NoError(t, err)
		cfg, _ := vc.Translate()
		detector := NewDetector(cfg)
		detector.FollowSymlinks = true
		paths, err := sources.DirectoryTargets(tt.source, detector.Sema, true)
		require.NoError(t, err)
		findings, err := detector.DetectFiles(paths)
		require.NoError(t, err)
		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}

func moveDotGit(t *testing.T, from, to string) {
	t.Helper()

	repoDirs, err := os.ReadDir("../testdata/repos")
	require.NoError(t, err)
	for _, dir := range repoDirs {
		if to == ".git" {
			_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), "dotGit"))
			if os.IsNotExist(err) {
				// dont want to delete the only copy of .git accidentally
				continue
			}
			os.RemoveAll(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), ".git"))
		}
		if !dir.IsDir() {
			continue
		}
		_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from))
		if os.IsNotExist(err) {
			continue
		}

		err = os.Rename(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from),
			fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), to))
		require.NoError(t, err)
	}
}
