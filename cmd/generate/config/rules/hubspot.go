package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func HubSpotAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations.",
		RuleID:      "hubspot-api-key",
		Regex: generateSemiGenericRegex([]string{"hubspot"},
			`[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`, true),

		Keywords: []string{"hubspot"},
	}

	// validate
	tps := []string{
		`const hubspotKey = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
		generateSampleSecret("hubspot", secrets.NewSecret(hex8_4_4_4_12())),
	}
	return validate(r, tps, nil)
}

func HubSpotPrivateAppAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a HubSpot Private App API Token, posing a risk to CRM data integrity and unauthorized marketing operations.",
		RuleID:      "hubspot-private-app-access-token",
		Regex: generateSemiGenericRegex([]string{"hubspot"},
			`pat-(?:eu|na)[0-9]-[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`, true),
		Keywords: []string{"hubspot", "pat-"},
	}

	// validate
	tps := []string{
		"const hubspotKey = pat-eu1-12345678-ABCD-ABCD-ABCD-1234567890AB", // gitleaks:allow
		"const hubspotKey = pat-na1-12345678-ABCD-ABCD-ABCD-1234567890AB", // gitleaks:allow
		generateSampleSecret("hubspot", "pat-eu1-"+secrets.NewSecret(hex8_4_4_4_12())),
		generateSampleSecret("hubspot", "pat-na1-"+secrets.NewSecret(hex8_4_4_4_12())),
	}
	fps := []string{
		// Regular HubSpot API Key
		`const hubspotKey = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
		// Developer API Tokens
		"eu1-1234-ABCD-1234-ABCD-1234567890AB", // gitleaks:allow
		"na1-1234-ABCD-1234-ABCD-1234567890AB", // gitleaks:allow
		generateSampleSecret("hubspot", "eu1-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("12"))),
		generateSampleSecret("hubspot", "na1-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("12"))),
	}

	return validate(r, tps, fps)
}

func HubSpotDeveloperAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a HubSpot Private App API Token, posing a risk to CRM data integrity and unauthorized marketing operations.",
		RuleID:      "hubspot-developer-access-token",
		Regex: generateSemiGenericRegex([]string{"hubspot"},
			`(?:eu|na)[0-9]-(?:[0-9A-F]{4}-){4}[0-9A-F]{12}`, true),
		Keywords: []string{"hubspot"},
	}

	// validate
	tps := []string{
		"const hubspotKey = eu1-1234-ABCD-1234-ABCD-1234567890AB", // gitleaks:allow
		"const hubspotKey = na1-1234-ABCD-1234-ABCD-1234567890AB", // gitleaks:allow
		generateSampleSecret("hubspot", "eu1-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("12"))),
		generateSampleSecret("hubspot", "na1-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("4"))+"-"+secrets.NewSecret(hex("12"))),
	}
	fps := []string{
		// Regular HubSpot API Key
		`const hubspotKey = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
		// Private App Access Tokens
		"pat-eu1-12345678-ABCD-ABCD-ABCD-1234567890AB", // gitleaks:allow
		"pat-na1-12345678-ABCD-ABCD-ABCD-1234567890AB", // gitleaks:allow
		generateSampleSecret("hubspot", "pat-eu1-"+secrets.NewSecret(hex8_4_4_4_12())),
		generateSampleSecret("hubspot", "pat-na1-"+secrets.NewSecret(hex8_4_4_4_12())),
	}

	return validate(r, tps, fps)
}
