package proxy

import (
	"io"
	"log"
	"net"
	"net/http"

	"github.com/st3v/uaa-authcode-proxy/util"
)

func Websocket(target string, fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !util.IsWebsocketRequest(r) {
			fallback.ServeHTTP(w, r)
			return
		}

		d, err := net.Dial("tcp", target)
		if err != nil {
			http.Error(w, "Error contacting backend server.", 500)
			log.Printf("error dialing websocket backend %s: %v", target, err)
			return
		}
		defer d.Close()

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Not a hijacker?", 500)
			return
		}

		nc, _, err := hj.Hijack()
		if err != nil {
			log.Printf("error hijacking request: %v", err)
			return
		}
		defer nc.Close()

		errChan := make(chan error, 2)
		cp := func(dst io.Writer, src io.Reader) {
			_, err := io.Copy(dst, src)
			errChan <- err
		}

		// copy dowstream
		go cp(d, nc)

		// copy upstream
		go cp(nc, d)

		err = r.Write(d)
		if err != nil {
			log.Printf("error writing request to target: %v", err)
			return
		}

		err = <-errChan
		if err != nil {
			log.Printf("error handling socket: %v\n", err)
		}
	})
}
