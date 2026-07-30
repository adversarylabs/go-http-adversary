package main
import "net/http"
import "time"
func main() { _ = &http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second} }
