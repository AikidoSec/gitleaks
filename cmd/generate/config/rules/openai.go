package rules

import (
	regexp "github.com/wasilibs/go-re2"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func OpenAI() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "openai-api-key",
		Description: "Found an OpenAI API Key, posing a risk of unauthorized access to AI services and data manipulation.",
		Regex:       regexp.MustCompile(`(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`),

		Keywords: []string{
			"T3BlbkFJ",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("openaiApiKey", "sk-"+secrets.NewSecret(alphaNumeric("20"))+"T3BlbkFJ"+secrets.NewSecret(alphaNumeric("20"))),
	}
	return validate(r, tps, nil)
}
