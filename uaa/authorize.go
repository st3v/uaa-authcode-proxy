package uaa

import (
	"context"
	"log"
	"net/http"
	"strings"

	gctx "github.com/gorilla/context"
	"github.com/st3v/uaa-authcode-proxy/util"

	"golang.org/x/oauth2"
)

func Authorize(oauth *oauth2.Config, session *session, httpClient *http.Client, handler http.Handler) http.Handler {
	return gctx.ClearHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := session.Token(r)
		if err != nil {
			// no token, go and get one
			redirectToAuthCodeURL(w, r, oauth, session)
			return
		}

		ctx := r.Context()
		if httpClient != nil {
			ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
		}

		// remember token in order to detect refreshs
		oldAccessToken := token.AccessToken

		// make sure token is valid, refresh if necessary
		token, err = oauth.TokenSource(ctx, token).Token()
		if err != nil {
			log.Printf("error getting token from token source: %v\n", err)
			redirectToAuthCodeURL(w, r, oauth, session)
			return
		}

		// has token been refreshed?
		if oldAccessToken != token.AccessToken {
			// check token scopes
			if !hasRequiredScopes(token, oauth.Scopes) {
				log.Println("insufficient scopes")
				http.Error(w, "insufficient permissions", http.StatusUnauthorized)
				return
			}

			// store new token
			session.SetToken(w, r, token)
		}

		handler.ServeHTTP(w, r)
	}))
}

func hasRequiredScopes(token *oauth2.Token, scopes []string) bool {
	str, ok := token.Extra("scope").(string)
	if !ok {
		return false
	}

	// uaa returns scopes a space-separated sting
	have := strings.Split(str, " ")

	contains := func(haystack []string, needle string) bool {
		for _, h := range haystack {
			// scopes are case-sensitive
			if h == needle {
				return true
			}
		}
		return false
	}

	for _, want := range scopes {
		if !contains(have, want) {
			return false
		}
	}

	return true
}

func redirectToAuthCodeURL(w http.ResponseWriter, r *http.Request, oauth *oauth2.Config, session *session) {
	// no need to redirect for websockets or xhr
	if util.IsWebsocketRequest(r) || util.IsXMLHTTPRequest(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// remember random state string in session
	state := util.RandomString(64)
	session.SetState(w, r, state)

	// redirect including including the state string
	url := oauth.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
