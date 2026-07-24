package excellent

import (
	"context"
	"net/http"
	"time"
)

func server(handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":8080",
		Handler:           http.MaxBytesHandler(handler, 1<<20),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func stop(ctx context.Context, srv *http.Server) error { return srv.Shutdown(ctx) }
