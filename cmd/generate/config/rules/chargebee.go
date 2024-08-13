package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ChargebeeAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Chargebee Access Token, posing a risk to subscription management, payment processing services and sensitive financial data.",
		RuleID:      "chargebee-access-token",
		Regex:       generateUniqueTokenRegex(`(test|live)_[0-9a-zA-Z]{32,34}`, false),
		Keywords: []string{
			"test_",
			"live_",
		},
	}

	// validate
	tps := []string{"chargebeeToken := \"test_" + secrets.NewSecret(alphaNumeric("32")) + "\""}
	fps := []string{
		"nonMatchingToken := \"" + secrets.NewSecret(alphaNumeric("32")) + "\"",
		"Test_HttpClientBasedGraphQlQueryPoster",
		"Test_SetupInvoiceAddressOnPOGCustomer",
		"Test_FetchAccountsWithUpdatedAtFilter",
		"Test_GetCustomerInvoiceAttachmentsInfo",
	}
	return validate(r, tps, fps)
}
