package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/initframs/vsic"
	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	ListenAddr string `toml:"listen_addr"`
	VsicAddr   string `toml:"vsic_addr"`

	JWTSecret string `toml:"jwt_secret"`
	UseTLS    bool   `toml:"use_tls"`

	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`

	MaxConnsPerIP int `toml:"max_conns_per_ip"`
}

var (
	ipConns = map[string]int{}
	mu      sync.Mutex
)

type Frame struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

func frameToVsic(f Frame) (string, bool) {
	switch f.Type {
	case "hello":
		if f.Data == "" {
			return "", false
		}
		return "HELLO " + f.Data, true
	case "msg":
		if f.Data == "" {
			return "", false
		}
		return "MSG " + f.Data, true
	case "ping":
		return "PING", true
	case "bye":
		return "BYE", true
	default:
		return "", false
	}
}

func vsicToFrame(line string) Frame {
	cmd, arg := vsic.ParseCommand(line)
	switch cmd {
	case "HELLO":
		return Frame{Type: "hello", Data: arg}
	case "MOTD":
		return Frame{Type: "motd", Data: arg}
	case "MSG":
		return Frame{Type: "msg", Data: arg}
	case "PONG":
		return Frame{Type: "pong"}
	case "CYA":
		return Frame{Type: "cya"}
	case "ERROR":
		return Frame{Type: "error", Data: arg}
	case "CONNECTED":
		return Frame{Type: "connected"}
	default:
		return Frame{Type: "msg", Data: line}
	}
}

func configPath() string {
	return filepath.Join(os.Getenv("HOME"), ".config/wssc/wssc.conf")
}

func loadConfig() Config {
	b, err := os.ReadFile(configPath())
	if err != nil {
		log.Fatal("config read error:", err)
	}

	var cfg Config
	if err := toml.Unmarshal(b, &cfg); err != nil {
		log.Fatal("invalid config:", err)
	}

	if cfg.MaxConnsPerIP <= 0 {
		cfg.MaxConnsPerIP = 3
	}

	return cfg
}

func validateJWT(tokenStr, secret string) bool {
	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	return err == nil && tok.Valid
}

func allowIP(ip string, max int) bool {
	mu.Lock()
	defer mu.Unlock()

	if ipConns[ip] >= max {
		return false
	}
	ipConns[ip]++
	return true
}

func releaseIP(ip string) {
	mu.Lock()
	defer mu.Unlock()
	ipConns[ip]--
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,

	CheckOrigin: func(r *http.Request) bool {
		return true // potentially will add checks later, but origin isnt trusted anyways
	},
}

func handle(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		ip, _, _ := net.SplitHostPort(r.RemoteAddr)

		if !allowIP(ip, cfg.MaxConnsPerIP) {
			http.Error(w, "too many connections", http.StatusTooManyRequests)
			return
		}
		defer releaseIP(ip)

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}

		if !validateJWT(strings.TrimPrefix(auth, "Bearer "), cfg.JWTSecret) {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()

		var conn net.Conn
		conn, err = net.Dial("tcp4", cfg.VsicAddr)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()

		vc := vsic.Wrap(conn, vsic.Config{
			MaxMsgSize: 4096,
			TimeoutSec: 120,
		})

		// ws to vsic
		go func() {
			for {
				_, msg, err := ws.ReadMessage()
				if err != nil {
					return
				}

				var f Frame
				if json.Unmarshal(msg, &f) != nil {
					continue
				}

				if line, ok := frameToVsic(f); ok {
					vc.WriteLine(line)
				}
			}
		}()

		// vsic to ws
		for {
			line, err := vc.ReadLine()
			if err != nil {
				return
			}

			out, _ := json.Marshal(vsicToFrame(line))

			ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			ws.WriteMessage(websocket.TextMessage, out)
		}
	}
}

func main() {
	cfg := loadConfig()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handle(cfg))

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: mux,
	}

	log.Println("wssc listening on", cfg.ListenAddr)

	if cfg.UseTLS {
		if cfg.TLSCert == "" || cfg.TLSKey == "" {
			log.Fatal("tls enabled but cert/key missing")
		}

		log.Fatal(server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey))
	}

	log.Fatal(server.ListenAndServe())
}
