package terrible

import (
	"io"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	_, _ = w.Write(body)
}

func run() error {
	srv := &http.Server{Addr: ":8080", Handler: http.HandlerFunc(handle)}
	return srv.ListenAndServe()
}
