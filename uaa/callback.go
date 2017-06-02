package uaa

import (
	"context"
	"log"
	"net/http"

	gctx "github.com/gorilla/context"

	"golang.org/x/oauth2"
)

func Callback(oauth *oauth2.Config, session Session, httpClient *http.Client, redirectTo string) http.Handler {
	return gctx.ClearHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get state string from session
		state, ok := session.Get(r, sessionKeyState).(string)
		if !ok {
			log.Println("missing or invalid state")
			http.Error(w, "missing or invalid state", http.StatusForbidden)
			return
		}

		// verify state string in request values
		if r.FormValue("state") != state {
			log.Printf("state mismatch, want: %q, have %q\n", state, r.FormValue("state"))
			http.Error(w, "state mismatch", http.StatusForbidden)
			return
		}

		ctx := r.Context()
		if httpClient != nil {
			ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
		}

		// exchange auth code for token
		token, err := oauth.Exchange(ctx, r.FormValue("code"))
		if err != nil {
			log.Printf("error exchanging token: %v\n", err)
			http.Error(w, "error exchanging token", http.StatusInternalServerError)
			return
		}

		// check token scopes
		if !hasRequiredScopes(token, oauth.Scopes) {
			log.Println("insufficient scopes")
			http.Error(w, "insufficient permissions", http.StatusUnauthorized)
			return
		}

		// remember token in session
		if err := session.Set(w, r, sessionKeyToken, token); err != nil {
			// just log it for now and move on
			// next request should trigger re-authentication
			log.Printf("error storing token in session: %v\n", err)
		}

		http.Redirect(w, r, redirectTo, http.StatusTemporaryRedirect)
	}))
}
