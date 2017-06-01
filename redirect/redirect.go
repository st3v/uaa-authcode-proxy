package redirect

import (
	"net"
	"net/http"
)

func Port(port string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, rport, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
			rport = "80"
		}

		if rport != port {
			r.URL.Host = net.JoinHostPort(host, port)
			http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

func Scheme(scheme string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Scheme != scheme {
			r.URL.Scheme = scheme
			http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
			return
		}

		handler.ServeHTTP(w, r)
	})
}
