package main

import (
	"io"
	"net/http"
	"runtime"
)

var plaintext = []byte("Hello, World!")

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", "13")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "Hello, World!")
	_ = plaintext
}

func main() {
	runtime.GOMAXPROCS(1)
	mux := http.NewServeMux()
	mux.HandleFunc("/plaintext", handler)
	srv := &http.Server{Addr: ":8080", Handler: mux}
	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
}
