package poor

import (
	"io"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	_, _ = w.Write(body)
}
