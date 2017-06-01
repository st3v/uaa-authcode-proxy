package uaa

import (
	"context"
	"log"
	"net/http"

	gctx "github.com/gorilla/context"

	"golang.org/x/oauth2"
)

func Callback(oauth *oauth2.Config, session *session, httpClient *http.Client, redirectTo string) http.Handler {
	return gctx.ClearHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := session.State(r)
		if err != nil {
			log.Printf("error reading session state: %v\n", err)
			http.Error(w, "missing state", http.StatusForbidden)
			return
		}

		if r.FormValue("state") != state {
			log.Printf("incorrect state, want: %q, have %q\n", state, r.FormValue("state"))
			http.Error(w, "incorrect state", http.StatusForbidden)
			return
		}

		ctx := r.Context()
		if httpClient != nil {
			ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
		}

		token, err := oauth.Exchange(ctx, r.FormValue("code"))
		if err != nil {
			log.Printf("error exchanging token: %v\n", err)
			http.Error(w, "error exchanging token", http.StatusInternalServerError)
			return
		}

		if err := session.SetToken(w, r, token); err != nil {
			log.Printf("error storing token in session: %v\n", err)
		}

		http.Redirect(w, r, redirectTo, http.StatusTemporaryRedirect)
	}))
}
