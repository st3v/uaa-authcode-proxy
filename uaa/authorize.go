package uaa

import (
	"context"
	"log"
	"math/rand"
	"net/http"
	"time"

	gctx "github.com/gorilla/context"

	"golang.org/x/oauth2"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

const letters = "abcdefghipqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func Authorize(scopes []string, oauth *oauth2.Config, session *session, httpClient *http.Client, handler http.Handler) http.Handler {
	return gctx.ClearHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := session.Token(r)
		if err != nil {
			redirectToAuthCodeURL(w, r, oauth, session)
			return
		}

		ctx := r.Context()
		if httpClient != nil {
			ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
		}

		// make sure token is valid, refresh if necessary
		token, err = oauth.TokenSource(ctx, token).Token()
		if err != nil {
			log.Printf("error getting token from token source: %v\n", err)
			redirectToAuthCodeURL(w, r, oauth, session)
		}
		session.SetToken(w, r, token)

		handler.ServeHTTP(w, r)
	}))
}

func redirectToAuthCodeURL(w http.ResponseWriter, r *http.Request, oauth *oauth2.Config, session *session) {
	state := randomString(64)
	session.SetState(w, r, state)
	url := oauth.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
