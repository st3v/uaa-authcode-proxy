package main

import (
	"flag"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

func init() {
	log.SetFlags(0)

	flag.StringVar(
		&listenAddr,
		"listen",
		getEnvString("LISTEN_ADDRESS", ":8080"),
		"address to listen on [LISTEN_ADDRESS]",
	)

	flag.StringVar(
		&backendAddr,
		"backend",
		getEnvString("BACKEND_ADDRESS", ""),
		"backend address [BACKEND_ADDRESS]",
	)

	flag.BoolVar(
		&proxyWebsockets,
		"proxy-websockets",
		getEnvBool("PROXY_WEBSOCKETS", true),
		"proxy websocket connections [PROXY_WEBSOCKETS]",
	)

	flag.StringVar(
		&redirectToPort,
		"redirect.port",
		getEnvString("REDIRECT_PORT", ""),
		"if a request has X-Forwarded-Port header set, it must equal the port specified here, otherwise redirect to the required port [REDIRECT_PORT]",
	)

	flag.StringVar(
		&redirectToProto,
		"redirect.proto",
		getEnvString("REDIRECT_PROTO", ""),
		"if a request has X-Forwarded-Proto header set, it must equal the protocol specified here, otherwise redirect to the required protocol [REDIRECT_PROTO]",
	)

	flag.StringVar(
		&uaaURL,
		"uaa.url",
		getEnvString("UAA_URL", ""),
		"UAA url [UAA_URL]",
	)

	flag.StringVar(
		&uaaInternalURL,
		"uaa.internal-url",
		getEnvString("UAA_INTERNAL_URL", ""),
		"UAA internal url used for token exchange, if not specified the regular UAA URL is being used [UAA_INTERNAL_URL]",
	)

	flag.StringVar(
		&uaaProxyClientName,
		"uaa.proxy-client.name",
		getEnvString("UAA_PROXY_CLIENT_NAME", ""),
		"UAA client name used by the proxy [UAA_PROXY_CLIENT_NAME]",
	)

	flag.StringVar(
		&uaaProxyClientID,
		"uaa.proxy-client.id",
		getEnvString("UAA_PROXY_CLIENT_ID", ""),
		"UAA client id used by the proxy [UAA_PROXY_CLIENT_ID]",
	)

	flag.StringVar(
		&uaaProxyClientSecret,
		"uaa.proxy-client.secret",
		getEnvString("UAA_PROXY_CLIENT_SECRET", ""),
		"UAA client secret used by the proxy [UAA_PROXY_CLIENT_SECRET]",
	)

	flag.StringVar(
		&uaaProxyClientRedirectURL,
		"uaa.proxy-client.redirect-url",
		getEnvString("UAA_PROXY_CLIENT_REDIRECT_URL", "http://localhost:8080/auth/callback"),
		"url to redirect user to after authentication, callback handler will be registered under the corresponding path [UAA_PROXY_CLIENT_REDIRECT_URL]",
	)

	flag.Var(
		&uaaRequiredScopes,
		"uaa.required-scopes",
		"comma-separated list of required scopes, UAA client for proxy has to be re-created whenever these scopes change [UAA_REQUIRED_SCOPES]",
	)

	flag.StringVar(
		&uaaCACertPath,
		"uaa.ca-cert",
		getEnvString("UAA_CA_CERT", ""),
		"path to CA cert for UAA [UAA_CA_CERT]",
	)

	flag.BoolVar(
		&uaaSkipTLSVerify,
		"uaa.skip-tls-validation",
		getEnvBool("UAA_SKIP_TLS_VALIDATION", false),
		"skip TLS cert validation [UAA_SKIP_TLS_VALIDATION]",
	)

	flag.StringVar(
		&sessionAuthKey,
		"session.auth-key",
		getEnvString("SESSION_AUTH_KEY", ""),
		"key to authenticate session cookies using HMAC, randomly generated if not specified [SESSION_AUTH_KEY]",
	)

	flag.StringVar(
		&sessionEncryptKey,
		"session.encrypt-key",
		getEnvString("SESSION_ENCRYPT_KEY", ""),
		"key to encrypt session cookies, randomly generated if less than 16 bytes [SESSION_ENCRYPT_KEY]",
	)

	flag.StringVar(
		&uaaAdminClientID,
		"uaa.admin-client.id",
		getEnvString("UAA_ADMIN_CLIENT_ID", ""),
		"UAA client id, used to register proxy client [UAA_ADMIN_CLIENT_ID]",
	)

	flag.StringVar(
		&uaaAdminClientSecret,
		"uaa.admin-client.secret",
		getEnvString("UAA_ADMIN_CLIENT_SECRET", ""),
		"UAA admin client secret, used to register proxy client [UAA_ADMIN_CLIENT_SECRET]",
	)

	flag.BoolVar(
		&uaaRegisterProxyClient,
		"uaa.register-proxy-client",
		getEnvBool("UAA_REGISTER_PROXY_CLIENT", false),
		"register UAA client for proxy [UAA_REGISTER_PROXY_CLIENT]",
	)

	flag.DurationVar(
		&uaaTokenTTL,
		"uaa.token-ttl",
		getEnvDuration("UAA_TOKEN_TTL", 2*time.Minute),
		"duration after which token expires, UAA client for proxy has to be re-created whenever this changes [UAA_TOKEN_TTL]",
	)
}

type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSlice) Set(v string) error {
	for _, str := range strings.Split(v, ",") {
		*s = append(*s, str)
	}
	return nil
}

func getEnvString(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}

	return v
}

func getEnvDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}

	d, err := time.ParseDuration(v)
	if err != nil {
		d = def
	}

	return d
}

func getEnvBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}

	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}

	return b
}
