package main
import ("io"; "net/http")
func h(w http.ResponseWriter, r *http.Request) { io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20)) }
