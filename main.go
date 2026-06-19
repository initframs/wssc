package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

type Config struct {
	ListenAddr  string
	VSICAddr    string
	AllowedHost string
	JWTSecret   string
	RateLimit   int
}

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config/wssc.conf")
}

func loadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		lines = append(lines, l)
	}

	if len(lines) < 4 {
		return Config{}, fmt.Errorf("need: listen, vsic, host, jwtsecret")
	}

	cfg := Config{
		ListenAddr:  lines[0],
		VSICAddr:    lines[1],
		AllowedHost: lines[2],
		JWTSecret:   lines[3],
		RateLimit:   10,
	}

	if len(lines) >= 5 {
		fmt.Sscanf(lines[4], "%d", &cfg.RateLimit)
	}

	return cfg, nil
}

type Frame struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

func validateJWT(tokenStr, secret string) bool {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	return err == nil && token.Valid
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func handleWS(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// can be spoofed
		if !strings.Contains(r.Host, cfg.AllowedHost) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if !validateJWT(strings.TrimPrefix(auth, "Bearer "), cfg.JWTSecret) {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("upgrade:", err)
			return
		}
		defer ws.Close()

		limiter := rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimit)

		tcp, err := net.Dial("tcp", cfg.VSICAddr)
		if err != nil {
			log.Println("tcp dial:", err)
			return
		}
		defer tcp.Close()

		ws.SetReadLimit(4096)
		ws.SetReadDeadline(time.Now().Add(30 * time.Second))
		ws.SetPongHandler(func(string) error {
			ws.SetReadDeadline(time.Now().Add(30 * time.Second))
			return nil
		})

		// ws to tcp
		go func() {
			defer tcp.Close()

			for {
				_, msg, err := ws.ReadMessage()
				if err != nil {
					return
				}

				if !limiter.Allow() {
					continue
				}

				var f Frame
				if err := json.Unmarshal(msg, &f); err != nil {
					continue
				}

				if f.Type != "msg" {
					continue
				}

				tcp.Write([]byte(f.Data + "\n"))
			}
		}()

		// tcp to ws
		sc := bufio.NewScanner(tcp)

		for sc.Scan() {
			line := sc.Text()

			f := Frame{
				Type: "msg",
				Data: line,
			}

			b, _ := json.Marshal(f)

			ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := ws.WriteMessage(websocket.TextMessage, b); err != nil {
				return
			}
		}

		if err := sc.Err(); err != nil {
			log.Println("tcp:", err)
		}
	}
}

func main() {
	cfg, err := loadConfig(configPath())
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleWS(cfg))

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Println("listening:", cfg.ListenAddr)
	log.Println("forwarding:", cfg.VSICAddr)

	log.Fatal(server.ListenAndServeTLS(
		"/etc/wssc/cert.pem",
		"/etc/wssc/key.pem",
	))
}
