package register

import (
	"time"

	"code.cloudfoundry.org/uaa-go-client/schema"
)

type option func(c *schema.OauthClient)

func WithGrantTypes(types ...string) option {
	return func(c *schema.OauthClient) {
		c.AuthorizedGrantTypes = types
	}
}

func WithScopes(scopes ...string) option {
	return func(c *schema.OauthClient) {
		c.Scope = scopes
	}
}

func WithAuthorities(auths ...string) option {
	return func(c *schema.OauthClient) {
		c.Authorities = auths
	}
}

func WithName(name string) option {
	return func(c *schema.OauthClient) {
		c.Name = name
	}
}

func WithTokenTTL(ttl time.Duration) option {
	return func(c *schema.OauthClient) {
		c.AccessTokenValidity = int(ttl.Seconds())
	}
}

func WithRedirectURLs(urls ...string) option {
	return func(c *schema.OauthClient) {
		c.RedirectUri = urls
	}
}
