package middleware

import "net/http"

type ResponseWriterWrapper struct {
	http.ResponseWriter
}

func (w *ResponseWriterWrapper) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// bufferedResponseWriter preserves the underlying writer capabilities,
// including Flusher and Hijacker through http.ResponseController, so they
// remain type-assertable while output is buffered.
type bufferedResponseWriter struct {
	*ResponseWriterWrapper
}

func (w *bufferedResponseWriter) FlushError() error {
	return http.NewResponseController(w.ResponseWriterWrapper).Flush()
}
