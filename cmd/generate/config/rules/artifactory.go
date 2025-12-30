package rules

import (
	"fmt"

	regexp "github.com/wasilibs/go-re2"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ArtifactoryAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "artifactory-api-key",
		Description: "Detected an Artifactory api key, posing a risk unauthorized access to the central repository.",
		Regex:       regexp.MustCompile(`\bAKCp[A-Za-z0-9]{69}\b`),
		Entropy:     4.5,
		Keywords:    []string{"akcp"},
	}

	// validate
	tps := []string{
		fmt.Sprintf("akcp=%s", secrets.NewSecret(`AKCp[A-Za-z0-9]{69}`)),
	}
	return validate(r, tps, nil)
}

func ArtifactoryReferenceToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "artifactory-reference-token",
		Description: "Detected an Artifactory reference token, posing a risk of impersonation and unauthorized access to the central repository.",
		Regex:       regexp.MustCompile(`\bcmVmd[A-Za-z0-9]{59}\b`),
		Entropy:     4.5,
		Keywords:    []string{"cmvmd"},
	}

	// validate
	tps := []string{
		fmt.Sprintf("cmvmd=%s", secrets.NewSecret(`cmVmd[A-Za-z0-9]{59}`)),
	}
	return validate(r, tps, nil)
}
