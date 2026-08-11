package middleware

import "net/http"

// responseRecorder intentionally captures only the base ResponseWriter API.
// It makes no transparent capability-preservation claim.
type responseRecorder struct {
	http.ResponseWriter
}
