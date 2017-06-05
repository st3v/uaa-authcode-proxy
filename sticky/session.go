package sticky

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
)

const cookieName = "JSESSIONID"

func Session(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(cookieName); err != nil {
			http.SetCookie(w, &http.Cookie{
				Name:  cookieName,
				Value: newSessionID(),
			})
		}
		handler.ServeHTTP(w, r)
	})
}

func newSessionID() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}
