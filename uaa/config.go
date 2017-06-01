package uaa

import (
	"fmt"

	"golang.org/x/oauth2"
)

func Config(url, clientID, clientSecret string, scopes []string, callbackURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/oauth/authorize", url),
			TokenURL: fmt.Sprintf("%s/oauth/token", url),
		},
		RedirectURL: callbackURL,
	}
}
