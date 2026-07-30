package main
import "net/http"
func main() { _ = &http.Server{Addr: ":8080"} }
