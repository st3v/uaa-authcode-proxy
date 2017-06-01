package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func HTTP(target *url.URL) http.Handler {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.Host = target.Host
			req.URL.Host = target.Host
			req.URL.Scheme = target.Scheme
			req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
			req.URL.RawQuery = combinedQuery(target, req.URL)
		},
	}
}

func combinedQuery(a, b *url.URL) string {
	queries := []string{}
	for _, q := range []string{a.RawQuery, b.RawQuery} {
		if q != "" {
			queries = append(queries, q)
		}
	}
	return strings.Join(queries, "&")
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
