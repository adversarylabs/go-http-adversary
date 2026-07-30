package main
import ("net/http"; "time")
func c() *http.Client { return &http.Client{Timeout: 10 * time.Second} }
