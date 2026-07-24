package average

import "net/http"

func run() error { return http.ListenAndServe(":8080", http.NewServeMux()) }
