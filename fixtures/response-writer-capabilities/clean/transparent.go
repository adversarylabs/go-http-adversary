package middleware

import (
	"bufio"
	"net"
	"net/http"
)

type ResponseWriterWrapper struct {
	http.ResponseWriter
}

// transparentWriter preserves direct Flusher and Hijacker assertions.
type transparentWriter struct {
	*ResponseWriterWrapper
}

func (w *transparentWriter) Flush() {}

func (w *transparentWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}
