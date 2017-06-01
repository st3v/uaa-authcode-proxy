package uaa

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	gctx "github.com/gorilla/context"

	"golang.org/x/oauth2"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

const letters = "abcdefghipqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func redirectToAuthCodeURL(w http.ResponseWriter, r *http.Request, oauth *oauth2.Config, session *session) {
	state := randomString(64)
	session.SetState(w, r, state)
	url := oauth.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

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

		// make sure token is valid, refresh it if necessary
		token, err = oauth.TokenSource(ctx, token).Token()
		if err != nil {
			log.Printf("error getting token from token source: %v\n", err)
			redirectToAuthCodeURL(w, r, oauth, session)
		}

		session.SetToken(w, r, token)

		// // TODO: think about whether we would like to do that for every request, this will put lots of additional load on the UAA
		// valid, err := checkToken(token, scopes, oauth, httpClient)
		// if err != nil {
		// 	log.Printf("error checking token: %v\n", err)
		// 	http.Error(w, "error verifying oauth2 token", http.StatusInternalServerError)
		// 	return
		// }

		// if !valid {
		// 	http.Error(w, "insufficient permissions", http.StatusUnauthorized)
		// 	return
		// }

		handler.ServeHTTP(w, r)
	}))
}

func checkToken(token *oauth2.Token, scopes []string, oauth *oauth2.Config, httpClient *http.Client) (bool, error) {
	u, err := url.Parse(oauth.AuthCodeURL("", oauth2.AccessTypeOnline))
	if err != nil {
		return false, errors.New("error parsing auth url")
	}

	u.Path = "/check_token"
	u.RawQuery = ""

	q := url.Values{}
	q.Add("token", token.AccessToken)
	for _, s := range scopes {
		q.Add("scopes", s)
	}

	req, err := http.NewRequest("POST", u.String(), strings.NewReader(q.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(q.Encode())))
	req.SetBasicAuth(oauth.ClientID, oauth.ClientSecret)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("error checking token: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			log.Printf("invalid token: %s\n", string(body))
		}
		resp.Body.Close()
		return false, nil
	}

	return true, nil
}

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
