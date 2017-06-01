package register

import (
	"time"

	"code.cloudfoundry.org/clock"
	"code.cloudfoundry.org/lager"
	uaago "code.cloudfoundry.org/uaa-go-client"
	"code.cloudfoundry.org/uaa-go-client/config"
	"code.cloudfoundry.org/uaa-go-client/schema"
)

type registrar struct {
	uaac uaago.Client
}

func Registrar(uaaURL, clientID, clientSecret string, caCertPath string, tlsSkipVerify bool) (*registrar, error) {
	config := &config.Config{
		UaaEndpoint:           uaaURL,
		ClientName:            clientID,
		ClientSecret:          clientSecret,
		CACerts:               caCertPath,
		SkipVerification:      tlsSkipVerify,
		MaxNumberOfRetries:    5,
		RetryInterval:         10 * time.Second,
		ExpirationBufferInSec: config.DefaultExpirationBufferInSec,
	}

	uaac, err := uaago.NewClient(new(noopLogger), config, clock.NewClock())
	return &registrar{uaac}, err
}

func (r *registrar) RegisterClient(id, secret string, opts ...option) error {
	client := &schema.OauthClient{
		ClientId:     id,
		ClientSecret: secret,
	}

	for _, opt := range opts {
		opt(client)
	}

	_, err := r.uaac.RegisterOauthClient(client)
	return err
}

type noopLogger struct{}

func (n *noopLogger) RegisterSink(lager.Sink)                    {}
func (n *noopLogger) Session(string, ...lager.Data) lager.Logger { return n }
func (n *noopLogger) SessionName() string                        { return "noop" }
func (n *noopLogger) Debug(string, ...lager.Data)                {}
func (n *noopLogger) Info(string, ...lager.Data)                 {}
func (n *noopLogger) Error(string, error, ...lager.Data)         {}
func (n *noopLogger) Fatal(string, error, ...lager.Data)         {}
func (n *noopLogger) WithData(lager.Data) lager.Logger           { return n }
