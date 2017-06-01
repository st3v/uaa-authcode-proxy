package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/st3v/uaa-authcode-proxy/proxy"
	"github.com/st3v/uaa-authcode-proxy/redirect"
	"github.com/st3v/uaa-authcode-proxy/uaa"
	"github.com/st3v/uaa-authcode-proxy/uaa/register"
)

// flags
var (
	listenAddr             string
	backendAddr            string
	hostname               string
	redirectToPort         string
	redirectToScheme       string
	proxyWebsockets        bool
	uaaURL                 string
	uaaAdminClientID       string
	uaaAdminClientSecret   string
	uaaRegisterProxyClient bool
	uaaProxyClientName     string
	uaaProxyClientID       string
	uaaProxyClientSecret   string
	uaaRequiredScopes      stringSlice
	uaaCACertPath          string
	uaaSkipTLSVerify       bool
	uaaTokenTTL            time.Duration
	sessionAuthKey         string
	sessionEncryptKey      string
)

const uaaCallbackPath = "/auth/callback"

func main() {
	flag.Parse()
	if len(uaaRequiredScopes) == 0 {
		flag.Set("uaa.required-scopes", getEnvString("UAA_REQUIRED_SCOPES", ""))
	}

	if backendAddr == "" {
		flag.Usage()
		log.Fatalln("must specify target address")
	}

	backend, err := url.Parse(backendAddr)
	if err != nil {
		log.Fatalf("error parsing url %q: %v\n", backendAddr, err)
	}

	callbackURL, err := callbackURL(listenAddr, hostname, redirectToPort, redirectToScheme, uaaCallbackPath)
	if err != nil {
		log.Fatal(err)
	}

	// register UAA client for proxy
	if uaaRegisterProxyClient {
		log.Println("Registering UAA client for proxy...")

		registrar, err := register.Registrar(
			uaaURL, uaaAdminClientID, uaaAdminClientSecret, uaaCACertPath, uaaSkipTLSVerify,
		)
		if err != nil {
			log.Fatalf("error creating UAA client registrar: %v\n", err)
		}

		if err := registrar.RegisterClient(
			uaaProxyClientID,
			uaaProxyClientSecret,
			register.WithName(uaaProxyClientName),
			register.WithGrantTypes("authorization_code", "refresh_token"),
			register.WithScopes(uaaRequiredScopes...),
			register.WithAuthorities("uaa.resource"),
			register.WithTokenTTL(uaaTokenTTL),
			register.WithRedirectURLs(callbackURL),
		); err != nil {
			log.Printf("error registering UAA client for proxy: %v\n", err)
		}
	}

	oauth := uaa.Config(uaaURL, uaaProxyClientID, uaaProxyClientSecret, uaaRequiredScopes, callbackURL)

	session := uaa.NewSessionStore([]byte(sessionAuthKey), []byte(sessionEncryptKey))

	caCertPool := x509.NewCertPool()

	if uaaCACertPath != "" {
		cert, err := ioutil.ReadFile(uaaCACertPath)
		if err != nil {
			log.Fatalf("error reading UAA CA cert: %v\n", err)
		}
		caCertPool.AppendCertsFromPEM(cert)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: uaaSkipTLSVerify,
			},
		},
	}

	// basic HTTP proxy
	server := proxy.HTTP(backend)

	// websocket proxy
	if proxyWebsockets {
		server = proxy.Websocket(backend.Host, server)
	}

	// oauth2 authorization handler
	server = uaa.Authorize(oauth, session, httpClient, server)

	// port redirection handler
	if redirectToPort != "" {
		server = redirect.Port(redirectToPort, server)
	}

	// scheme redirection handler
	if redirectToScheme != "" {
		server = redirect.Scheme(redirectToScheme, server)
	}

	mux := http.NewServeMux()
	mux.Handle("/", server)
	mux.Handle(uaaCallbackPath, uaa.Callback(oauth, session, httpClient, "/")) // TODO: get rid of redirectURL, store in session

	log.Printf("Listening on %s...", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func callbackURL(listenAddr, hostname, port, scheme, path string) (string, error) {
	listenHost, listenPort, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", fmt.Errorf("invalid listen address: %v", err)
	}

	if hostname == "" {
		hostname = listenHost
	}

	if port == "" {
		port = listenPort
	}

	if scheme == "" {
		scheme = "http"
	}

	return fmt.Sprintf("%s://%s:%s%s", scheme, hostname, port, path), nil
}
