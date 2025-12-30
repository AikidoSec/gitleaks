package main

import (
	"os"
	"strings"
	"text/template"
	"unicode"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/config"
)

const (
	templatePath = "rules/config.tmpl"
)

//go:generate go run $GOFILE ../../../config/gitleaks.toml

func main() {
	if len(os.Args) < 2 {
		os.Stderr.WriteString("Specify path to the gitleaks.toml config\n")
		os.Exit(2)
	}
	gitleaksConfigPath := os.Args[1]

	configRules := []*config.Rule{
		rules.AdafruitAPIKey(),
		rules.AdobeClientID(),
		rules.AdobeClientSecret(),
		rules.AgeSecretKey(),
		rules.Airtable(),
		rules.AlgoliaApiKey(),
		rules.AlibabaAccessKey(),
		rules.AlibabaSecretKey(),
		rules.ArtifactoryAPIKey(),
		rules.ArtifactoryReferenceToken(),
		rules.AsanaClientID(),
		rules.AsanaClientSecret(),
		rules.Atlassian(),
		rules.Authress(),
		rules.AWS(),
		rules.BitBucketClientID(),
		rules.BitBucketClientSecret(),
		rules.BittrexAccessKey(),
		rules.BittrexSecretKey(),
		rules.Beamer(),
		rules.ChargebeeAccessToken(),
		rules.CodecovAccessToken(),
		rules.CoinbaseAccessToken(),
		rules.Clojars(),
		rules.ConfluentAccessToken(),
		rules.ConfluentSecretKey(),
		rules.Contentful(),
		rules.Databricks(),
		rules.DatadogtokenAccessToken(),
		rules.DefinedNetworkingAPIToken(),
		rules.DigitalOceanPAT(),
		rules.DigitalOceanOAuthToken(),
		rules.DigitalOceanRefreshToken(),
		rules.DiscordAPIToken(),
		rules.DiscordClientID(),
		rules.DiscordClientSecret(),
		rules.Doppler(),
		rules.DropBoxAPISecret(),
		rules.DropBoxLongLivedAPIToken(),
		rules.DropBoxShortLivedAPIToken(),
		rules.DroneciAccessToken(),
		rules.Duffel(),
		rules.Dynatrace(),
		rules.EasyPost(),
		rules.EasyPostTestAPI(),
		rules.EtsyAccessToken(),
		rules.Facebook(),
		rules.FastlyAPIToken(),
		rules.FinicityClientSecret(),
		rules.FinicityAPIToken(),
		rules.FlickrAccessToken(),
		rules.FinnhubAccessToken(),
		rules.FlutterwavePublicKey(),
		rules.FlutterwaveSecretKey(),
		rules.FlutterwaveEncKey(),
		rules.FrameIO(),
		rules.FreshbooksAccessToken(),
		rules.GoCardless(),
		// TODO figure out what makes sense for GCP
		// rules.GCPServiceAccount(),
		rules.GCPAPIKey(),
		rules.GitHubPat(),
		rules.GitHubFineGrainedPat(),
		rules.GitHubOauth(),
		rules.GitHubApp(),
		rules.GitHubRefresh(),
		rules.GitlabPat(),
		rules.GitlabPipelineTriggerToken(),
		rules.GitlabRunnerRegistrationToken(),
		rules.GitterAccessToken(),
		rules.GrafanaApiKey(),
		rules.GrafanaCloudApiToken(),
		rules.GrafanaServiceAccountToken(),
		rules.Hashicorp(),
		rules.HashicorpField(),
		rules.Heroku(),
		rules.HubSpot(),
		rules.HuggingFaceAccessToken(),
		rules.HuggingFaceOrganizationApiToken(),
		rules.Intercom(),
		rules.JFrogAPIKey(),
		rules.JFrogIdentityToken(),
		rules.JWT(),
		rules.JWTBase64(),
		rules.KrakenAccessToken(),
		rules.KucoinAccessToken(),
		rules.KucoinSecretKey(),
		rules.LaunchDarklyAccessToken(),
		rules.LinearAPIToken(),
		rules.LinearClientSecret(),
		rules.LinkedinClientID(),
		rules.LinkedinClientSecret(),
		rules.LobAPIToken(),
		rules.LobPubAPIToken(),
		rules.MailChimp(),
		rules.MailGunPubAPIToken(),
		rules.MailGunPrivateAPIToken(),
		rules.MailGunSigningKey(),
		rules.MapBox(),
		rules.MattermostAccessToken(),
		rules.MessageBirdAPIToken(),
		rules.MessageBirdClientID(),
		rules.NetlifyAccessToken(),
		rules.NewRelicUserID(),
		rules.NewRelicUserKey(),
		rules.NewRelicBrowserAPIKey(),
		rules.NPM(),
		rules.NytimesAccessToken(),
		rules.OktaAccessToken(),
		rules.OpenAI(),
		rules.PlaidAccessID(),
		rules.PlaidSecretKey(),
		rules.PlaidAccessToken(),
		rules.PlanetScalePassword(),
		rules.PlanetScaleAPIToken(),
		rules.PlanetScaleOAuthToken(),
		rules.PostManAPI(),
		rules.Prefect(),
		rules.PrivateKey(),
		rules.PulumiAPIToken(),
		rules.PyPiUploadToken(),
		rules.RapidAPIAccessToken(),
		rules.ReadMe(),
		rules.RubyGemsAPIToken(),
		rules.ScalingoAPIToken(),
		rules.SendbirdAccessID(),
		rules.SendbirdAccessToken(),
		rules.SendGridAPIToken(),
		rules.SendInBlueAPIToken(),
		rules.SentryAccessToken(),
		rules.SettlemintApplicationAccessToken(),
		rules.SettlemintPersonalAccessToken(),
		rules.SettlemintServiceAccessToken(),
		rules.ShippoAPIToken(),
		rules.ShopifyAccessToken(),
		rules.ShopifyCustomAccessToken(),
		rules.ShopifyPrivateAppAccessToken(),
		rules.ShopifySharedSecret(),
		rules.SidekiqSecret(),
		rules.SidekiqSensitiveUrl(),
		rules.SlackBotToken(),
		rules.SlackUserToken(),
		rules.SlackAppLevelToken(),
		rules.SlackConfigurationToken(),
		rules.SlackConfigurationRefreshToken(),
		rules.SlackLegacyBotToken(),
		rules.SlackLegacyWorkspaceToken(),
		rules.SlackLegacyToken(),
		rules.SlackWebHookUrl(),
		rules.Snyk(),
		rules.StripeAccessToken(),
		rules.SquareAccessToken(),
		rules.SquareSpaceAccessToken(),
		rules.SumoLogicAccessID(),
		rules.SumoLogicAccessToken(),
		rules.TeamsWebhook(),
		rules.TelegramBotToken(),
		rules.TravisCIAccessToken(),
		rules.Twilio(),
		rules.TwitchAPIToken(),
		rules.TwitterAPIKey(),
		rules.TwitterAPISecret(),
		rules.TwitterAccessToken(),
		rules.TwitterAccessSecret(),
		rules.TwitterBearerToken(),
		rules.Typeform(),
		rules.VaultBatchToken(),
		rules.VaultServiceToken(),
		rules.YandexAPIKey(),
		rules.YandexAWSAccessToken(),
		rules.YandexAccessToken(),
		rules.ZendeskSecretKey(),
		rules.GenericCredential(),
		rules.InfracostAPIToken(),
	}

	// ensure rules have unique ids
	ruleLookUp := make(map[string]config.Rule, len(configRules))
	for _, rule := range configRules {
		// check if rule is in ruleLookUp
		if _, ok := ruleLookUp[rule.RuleID]; ok {
			log.Fatal().Msgf("rule id %s is not unique", rule.RuleID)
		}
		// TODO: eventually change all the signatures to get ride of this
		// nasty dereferencing.
		ruleLookUp[rule.RuleID] = *rule
	}

	funcs := template.FuncMap{
		// Simple arithmetic helpers for templates.
		"sub":       func(a, b int) int { return a - b },
		"hasPrefix": func(s, prefix string) bool { return strings.HasPrefix(s, prefix) },

		// tomlRegex renders allowlist regexes in a TOML-safe way while keeping output close
		// to the existing config:
		// - Simple identifiers like "sumOf" use basic strings.
		// - Everything else uses TOML literal strings ('''...''') so backslashes don't need escaping.
		"tomlRegex": func(v any) string {
			s, ok := v.(interface{ String() string })
			if !ok {
				return `""`
			}
			str := s.String()

			isSimple := true
			for _, r := range str {
				if !(unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_') {
					isSimple = false
					break
				}
			}
			if isSimple {
				return `"` + str + `"`
			}
			return "'''" + str + "'''"
		},
	}

	tmpl, err := template.New(templatePath).Funcs(funcs).ParseFiles(templatePath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse template")
	}

	f, err := os.Create(gitleaksConfigPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create rules.toml")
	}

	// ParseFiles names templates by their base filename, not full path.
	// Since we build the root with templatePath, execute the parsed template by base name.
	if err = tmpl.ExecuteTemplate(f, "config.tmpl", config.Config{Rules: ruleLookUp}); err != nil {
		log.Fatal().Err(err).Msg("could not execute template")
	}

}
