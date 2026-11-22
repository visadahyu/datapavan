// SPDX-License-Identifier: Apache-2.0

// The relay lab's stand-in for an ODoH target (scripts/relaylab.sh, ADR 0055): an HTTPS server that writes each
// request it receives to its output as one JSON line (protocol, method, host, URI, every header, the body's length
// and SHA-256, the names of any trailers it declares) and answers it, so that the test can read exactly what the
// relay forwarded. It answers 200 with application/oblivious-dns-message and "answer of NAME to SHA256", the status
// a body "status-NNN" asks for, or N bytes for a body "big-N"; every answer carries headers that the relay must not
// pass on under its own origin: a cookie, Server, CORS, Clear-Site-Data, reporting, a redirect's Location and more.
// Go's standard library only.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

type record struct {
	Target     string              `json:"target"`
	Proto      string              `json:"proto"`
	Method     string              `json:"method"`
	Host       string              `json:"host"`
	URI        string              `json:"uri"`
	Headers    map[string][]string `json:"headers"`
	BodyLength int                 `json:"body_length"`
	BodySHA256 string              `json:"body_sha256"`
	Trailers   []string            `json:"trailers"`
}

func main() {
	name := flag.String("name", "", "the target's name in the records")
	listen := flag.String("listen", ":443", "address to listen on")
	cert := flag.String("cert", "", "certificate (PEM)")
	key := flag.String("key", "", "private key (PEM)")
	http1 := flag.Bool("http1", false, "offer HTTP/1.1 only, not HTTP/2")
	flag.Parse()
	var mu sync.Mutex
	out := json.NewEncoder(os.Stdout)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])
		mu.Lock()
		trailers := []string{}
		for k := range r.Trailer {
			trailers = append(trailers, k)
		}
		_ = out.Encode(record{*name, r.Proto, r.Method, r.Host, r.RequestURI, r.Header, len(body), digest, trailers})
		mu.Unlock()
		status, big := http.StatusOK, 0
		text := string(body)
		if strings.HasPrefix(text, "status-") {
			if n, err := strconv.Atoi(strings.TrimPrefix(text, "status-")); err == nil && n >= 200 && n < 600 {
				status = n
			}
		}
		if strings.HasPrefix(text, "big-") {
			if n, err := strconv.Atoi(strings.TrimPrefix(text, "big-")); err == nil && n > 0 && n <= 64<<20 {
				big = n
			}
		}
		h := w.Header()
		h.Set("Content-Type", "application/oblivious-dns-message")
		h.Set("Cache-Control", "no-store")
		h.Set("Server", "relaylab-stub-"+*name)
		h.Add("Set-Cookie", "tracker=stub-"+*name+"; Path=/")
		h.Set("X-Relaylab-Target", *name)
		h.Set("Clear-Site-Data", `"*"`)
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Nel", `{"report_to":"stub","max_age":86400}`)
		h.Set("Report-To", `{"group":"stub","max_age":86400,"endpoints":[{"url":"https://report.example/"}]}`)
		h.Set("Location", "https://elsewhere.example/")
		h.Set("Link", "<https://elsewhere.example/>; rel=preload")
		h.Set("Refresh", "0; url=https://elsewhere.example/")
		h.Set("Content-Disposition", "attachment")
		h.Set("Cross-Origin-Resource-Policy", "cross-origin")
		w.WriteHeader(status)
		if big > 0 {
			chunk := []byte(strings.Repeat("x", 32<<10))
			for sent := 0; sent < big; sent += len(chunk) {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
			return
		}
		fmt.Fprintf(w, "answer of %s to %s", *name, digest)
	})
	server := &http.Server{Addr: *listen, Handler: handler, ErrorLog: log.New(io.Discard, "", 0)}
	if *http1 {
		server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	}
	log.SetFlags(0)
	log.Printf("relaylab-stub %s on %s (http1 only: %v)", *name, *listen, *http1)
	if err := server.ListenAndServeTLS(*cert, *key); err != nil {
		log.Fatal(err)
	}
}
