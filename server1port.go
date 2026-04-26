// server1port.go
package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	controlReadTimeout  = 90 * time.Second
	controlPingInterval = 30 * time.Second
	reverseAttachTTL    = 30 * time.Second
)

var (
	flagListenWS  = flag.String("ws", ":80", "Shared listen addr for WS and HTTP proxy")
	flagProxyAddr = flag.String("proxy", "", "Deprecated: proxy now shares the -ws listener")
	flagAuthKey   = flag.String("k", os.Getenv("AUTH_KEY"), "Auth key (or set AUTH_KEY)")
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type ctrlConn struct {
	c  *websocket.Conn
	mu sync.Mutex
}

func (c *ctrlConn) sendText(msg string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.c.WriteMessage(websocket.TextMessage, []byte(msg))
}

func (c *ctrlConn) sendPing() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.c.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(5*time.Second))
}

type pendingConn struct {
	clientID string
	conn     net.Conn
	initial  []byte
	timer    *time.Timer
}

var (
	regMu sync.RWMutex
	reg   = map[string]*ctrlConn{}
)

var (
	waitMu sync.Mutex
	wait   = map[string]*pendingConn{}
)

func main() {
	rand.Seed(time.Now().UnixNano())
	flag.Parse()
	if *flagAuthKey == "" {
		log.Fatalf("Auth key required (-k or AUTH_KEY)")
	}
	if *flagProxyAddr != "" && *flagProxyAddr != *flagListenWS {
		log.Printf("[proxy] ignoring deprecated -proxy=%s; proxy now shares %s", *flagProxyAddr, *flagListenWS)
	}

	srv := &http.Server{
		Addr:    *flagListenWS,
		Handler: http.HandlerFunc(routeRequest),
	}
	log.Printf("[server] listening on %s for WS + HTTP proxy", *flagListenWS)
	log.Fatal(srv.ListenAndServe())
}

func routeRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	if websocket.IsWebSocketUpgrade(r) {
		switch r.URL.Path {
		case "/ws":
			handleWSForward(w, r)
			return
		case "/ws/control":
			handleControlWS(w, r)
			return
		case "/ws/data":
			handleDataWS(w, r)
			return
		}
	}
	httpProxyHandler(w, r)
}

func checkAuthFromHeaders(r *http.Request) (clientID string, ok bool) {
	if v := r.Header.Get("Proxy-Authorization"); v != "" {
		const prefix = "Basic "
		if len(v) > len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
			b := strings.TrimSpace(v[len(prefix):])
			if dec, err := base64.StdEncoding.DecodeString(b); err == nil {
				parts := strings.SplitN(string(dec), ":", 2)
				if len(parts) == 2 && parts[1] == *flagAuthKey {
					return parts[0], true
				}
			}
		}
	}
	if r.Header.Get("X-Auth-Key") == *flagAuthKey {
		cid := r.Header.Get("X-Client-Id")
		if cid != "" {
			return cid, true
		}
	}
	return "", false
}

func genConnID() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func normalizeTarget(raw string, defaultPort string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	_, _, err := net.SplitHostPort(raw)
	if err == nil {
		return raw
	}
	if addrErr, ok := err.(*net.AddrError); ok && strings.Contains(addrErr.Err, "missing port") {
		return net.JoinHostPort(raw, defaultPort)
	}
	if strings.Count(raw, ":") >= 2 && !strings.HasPrefix(raw, "[") && !strings.Contains(raw, "]:") {
		return net.JoinHostPort(raw, defaultPort)
	}
	if strings.Contains(raw, ":") && !strings.Contains(raw, "]") {
		return raw
	}
	return net.JoinHostPort(raw, defaultPort)
}

func buildForwardRequest(r *http.Request, dst string) ([]byte, error) {
	req := r.Clone(r.Context())
	req.RequestURI = ""
	if req.URL == nil {
		req.URL = &url.URL{}
	}
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Host = dst

	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func registerPending(clientID, cid string, conn net.Conn, initial []byte) {
	p := &pendingConn{
		clientID: clientID,
		conn:     conn,
		initial:  initial,
	}
	p.timer = time.AfterFunc(reverseAttachTTL, func() {
		waitMu.Lock()
		cur, ok := wait[cid]
		if ok && cur == p {
			delete(wait, cid)
		}
		waitMu.Unlock()
		if ok {
			_ = p.conn.Close()
			log.Printf("[reverse] attach timeout client=%s cid=%s", clientID, cid)
		}
	})

	waitMu.Lock()
	wait[cid] = p
	waitMu.Unlock()
}

func popPending(cid string) (*pendingConn, bool) {
	waitMu.Lock()
	p, ok := wait[cid]
	if ok {
		delete(wait, cid)
	}
	waitMu.Unlock()
	if !ok {
		return nil, false
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	return p, true
}

func handleWSForward(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth-Key") != *flagAuthKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	mt, data, err := conn.ReadMessage()
	if err != nil || mt != websocket.TextMessage {
		return
	}

	dst := normalizeTarget(string(data), "80")
	if dst == "" {
		return
	}

	tcpConn, err := net.DialTimeout("tcp", dst, 15*time.Second)
	if err != nil {
		return
	}
	defer tcpConn.Close()

	bridgeTCPWS(tcpConn, conn)
}

func handleControlWS(w http.ResponseWriter, r *http.Request) {
	clientID, ok := checkAuthFromHeaders(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadLimit(1 << 20)
	conn.SetReadDeadline(time.Now().Add(controlReadTimeout))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(controlReadTimeout))
	})

	ctrl := &ctrlConn{c: conn}

	regMu.Lock()
	if prev, ok := reg[clientID]; ok && prev != nil && prev.c != nil && prev.c != conn {
		_ = prev.c.Close()
	}
	reg[clientID] = ctrl
	regMu.Unlock()

	log.Printf("[control] client registered: %s", clientID)

	stopPing := make(chan struct{})
	go func() {
		t := time.NewTicker(controlPingInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := ctrl.sendPing(); err != nil {
					return
				}
			case <-stopPing:
				return
			}
		}
	}()

	defer func() {
		close(stopPing)
		regMu.Lock()
		if cur, ok := reg[clientID]; ok && cur.c == conn {
			delete(reg, clientID)
		}
		regMu.Unlock()
		log.Printf("[control] client disconnected: %s", clientID)
	}()

	for {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.TextMessage {
			continue
		}
		line := strings.TrimSpace(string(msg))
		if !strings.HasPrefix(strings.ToUpper(line), "CLOSE ") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		if p, ok := popPending(parts[1]); ok {
			_ = p.conn.Close()
		}
	}
}

func handleDataWS(w http.ResponseWriter, r *http.Request) {
	clientID, ok := checkAuthFromHeaders(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	cid := r.URL.Query().Get("cid")
	if cid == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("missing cid"))
		return
	}

	p, ok := popPending(cid)
	if !ok {
		w.WriteHeader(http.StatusGone)
		return
	}
	if p.clientID != clientID {
		_ = p.conn.Close()
		w.WriteHeader(http.StatusForbidden)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		_ = p.conn.Close()
		return
	}
	defer conn.Close()
	defer p.conn.Close()

	if len(p.initial) > 0 {
		if err := conn.WriteMessage(websocket.BinaryMessage, p.initial); err != nil {
			return
		}
	}

	bridgeTCPWS(p.conn, conn)
}

func httpProxyHandler(w http.ResponseWriter, r *http.Request) {
	clientID, ok := checkAuthFromHeaders(r)
	if !ok {
		w.Header().Set("Proxy-Authenticate", `Basic realm="P1-Proxy"`)
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusProxyAuthRequired)
		_, _ = w.Write([]byte("Proxy Authentication Required"))
		return
	}

	var (
		dst     string
		initial []byte
		err     error
	)

	if r.Method == http.MethodConnect {
		dst = normalizeTarget(r.Host, "443")
	} else {
		if r.URL == nil || r.URL.Host == "" {
			http.Error(w, "absolute-form required for non-CONNECT", http.StatusBadRequest)
			return
		}
		dst = normalizeTarget(r.URL.Host, "80")
		initial, err = buildForwardRequest(r, dst)
		if err != nil {
			http.Error(w, "failed to serialize request", http.StatusBadGateway)
			return
		}
	}
	if dst == "" {
		http.Error(w, "missing destination", http.StatusBadRequest)
		return
	}

	regMu.RLock()
	ctrl := reg[clientID]
	regMu.RUnlock()
	if ctrl == nil {
		http.Error(w, "client offline", http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}

	if r.Method == http.MethodConnect {
		_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = rw.Flush()
	}

	cid := genConnID()
	registerPending(clientID, cid, conn, initial)

	if err := ctrl.sendText("OPEN " + cid + " " + dst); err != nil {
		if p, ok := popPending(cid); ok {
			_ = p.conn.Close()
		}
		return
	}
}

func bridgeTCPWS(tcp net.Conn, ws *websocket.Conn) {
	errc := make(chan error, 2)
	go func() { errc <- copyTCPToWS(tcp, ws) }()
	go func() { errc <- copyWSToTCP(ws, tcp) }()
	<-errc
}

func copyTCPToWS(r net.Conn, ws *websocket.Conn) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if err2 := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err2 != nil {
				return err2
			}
		}
		if err != nil {
			return err
		}
	}
}

func copyWSToTCP(ws *websocket.Conn, w net.Conn) error {
	for {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			return err
		}
		if mt != websocket.BinaryMessage {
			continue
		}
		if len(data) > 0 {
			if _, err := w.Write(data); err != nil {
				return err
			}
		}
	}
}
