package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/st3v/uaa-proxy/proxy"
	"github.com/st3v/uaa-proxy/redirect"
	"github.com/st3v/uaa-proxy/uaa"
	"github.com/st3v/uaa-proxy/uaa/register"
)

// flags
var (
	listenAddr                string
	backendAddr               string
	redirectToPort            string
	redirectToScheme          string
	proxyWebsockets           bool
	uaaURL                    string
	uaaAdminClientID          string
	uaaAdminClientSecret      string
	uaaRegisterProxyClient    bool
	uaaProxyClientName        string
	uaaProxyClientID          string
	uaaProxyClientSecret      string
	uaaProxyClientRedirectURL string
	uaaRequiredScopes         stringSlice
	uaaCACertPath             string
	uaaSkipTLSVerify          bool
	uaaTokenTTL               time.Duration
	sessionAuthKey            string
	sessionEncryptKey         string
)

const defaultSessionName = "uaaproxy"

func main() {
	flag.Parse()
	if len(uaaRequiredScopes) == 0 {
		flag.Set("uaa.required-scopes", getEnvString("UAA_REQUIRED_SCOPES", ""))
	}

	if backendAddr == "" {
		flag.Usage()
		log.Fatalln("Must specify target address")
	}

	backend, err := url.Parse(backendAddr)
	if err != nil {
		log.Fatalf("Error parsing URL %q: %v\n", backendAddr, err)
	}

	redirectURL, err := url.Parse(uaaProxyClientRedirectURL)
	if err != nil {
		log.Fatalf("Error parsing UAA redirect URL %q: %v\n", uaaProxyClientRedirectURL, err)
	}

	// register UAA client for proxy
	if uaaRegisterProxyClient {
		log.Println("Registering UAA client for proxy...")

		registrar, err := register.Registrar(
			uaaURL, uaaAdminClientID, uaaAdminClientSecret, uaaCACertPath, uaaSkipTLSVerify,
		)
		if err != nil {
			log.Fatalf("Error creating UAA client registrar: %v\n", err)
		}

		err = registrar.RegisterClient(
			uaaProxyClientID,
			uaaProxyClientSecret,
			register.WithName(uaaProxyClientName),
			register.WithGrantTypes("authorization_code", "refresh_token"),
			register.WithScopes(uaaRequiredScopes...),
			register.WithAuthorities("uaa.resource"),
			register.WithTokenTTL(uaaTokenTTL),
			register.WithRedirectURLs(redirectURL.String()),
		)

		if err != nil {
			log.Printf("Error registering UAA client for proxy: %v\n", err)
		} else {
			log.Println("Done registering UAA client for proxy")
		}
	}

	oauth := uaa.Config(uaaURL, uaaProxyClientID, uaaProxyClientSecret, uaaRequiredScopes, redirectURL.String())

	session := uaa.NewSessionStore(defaultSessionName, []byte(sessionAuthKey), []byte(sessionEncryptKey))

	caCertPool := x509.NewCertPool()

	if uaaCACertPath != "" {
		cert, err := ioutil.ReadFile(uaaCACertPath)
		if err != nil {
			log.Fatalf("Error reading UAA CA cert: %v\n", err)
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
	mux.Handle(redirectURL.Path, uaa.Callback(oauth, session, httpClient))

	log.Printf("Listening on %s...", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}
