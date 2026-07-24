package good

import (
	"encoding/json"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	var request struct{ Name string }
	_ = json.NewDecoder(r.Body).Decode(&request)
}
