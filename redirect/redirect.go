package redirect

import (
	"net"
	"net/http"
)

// ForwardedPort returns a handler that checks if the X-Forwarded-Port header
// is set. If it is, the handler verifies that it equals the required port,
// otherwise the original request gets redirected to the required port.
func ForwardedPort(port string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.Header.Get("X-Forwarded-Port"); p != "" && p != port {
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				host = r.Host
			}

			r.URL.Host = net.JoinHostPort(host, port)
			http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// ForwardedPort returns a handler that checks if the X-Forwarded-Proto header
// is set. If it is, the handler verifies that it equals the required protocol,
// otherwise the original request gets redirected to the required protocol.
func ForwardedProto(proto string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" && p != proto {
			r.URL.Host = r.Host
			r.URL.Scheme = proto
			http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
			return
		}
		handler.ServeHTTP(w, r)
	})
}
