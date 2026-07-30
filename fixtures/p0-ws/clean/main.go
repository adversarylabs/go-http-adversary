package main
import (
  "net/http"
  "github.com/gorilla/websocket"
)
var up = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "https://example.com" }}
