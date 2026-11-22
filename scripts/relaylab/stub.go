// SPDX-License-Identifier: Apache-2.0

// The relay lab's stand-in for an ODoH target (scripts/relaylab.sh, ADR 0055): an HTTPS server that writes each
// request it receives to its output as one JSON line (protocol, method, host, URI, every header, the body's length
// and SHA-256) and answers it, so that the test can read exactly what the relay forwarded. It answers 200 with
// application/oblivious-dns-message and "answer of NAME to SHA256", or the status a body "status-NNN" asks for,
// and adds a cookie and a Server header that the relay must not pass on. Go's standard library only.
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
		_ = out.Encode(record{*name, r.Proto, r.Method, r.Host, r.RequestURI, r.Header, len(body), digest})
		mu.Unlock()
		status := http.StatusOK
		if text := string(body); strings.HasPrefix(text, "status-") {
			if n, err := strconv.Atoi(strings.TrimPrefix(text, "status-")); err == nil && n >= 200 && n < 600 {
				status = n
			}
		}
		w.Header().Set("Content-Type", "application/oblivious-dns-message")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Server", "relaylab-stub-"+*name)
		w.Header().Add("Set-Cookie", "tracker=stub-"+*name+"; Path=/")
		w.Header().Set("X-Relaylab-Target", *name)
		w.WriteHeader(status)
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
