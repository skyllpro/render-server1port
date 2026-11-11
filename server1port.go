// server-doraemon-tun.go
// Tunnel server: 1 WebSocket persistent <-> yamux multiplex.
// Auth: pre-shared key qua header X-Auth-Key (cho client) hoặc Proxy-Authorization Basic (cho user).
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
	"golang.org/x/time/rate"
)

// ----------------- flags -----------------
var (
	flagListenWS  = flag.String("ws", "", "Plain WS listen addr (mux endpoint)")
	flagListenWSS = flag.String("wss", "", "TLS WSS listen addr (mux endpoint); empty disables WSS")
	flagTLSCert   = flag.String("tls-cert", "", "TLS certificate file for -wss")
	flagTLSKey    = flag.String("tls-key", "", "TLS private key file for -wss")
	flagProxyAddr = flag.String("proxy", "", "HTTP proxy listen addr (CONNECT entry)")
	flagProxyTLS  = flag.String("proxys", "", "HTTPS proxy listen addr; empty disables HTTPS proxy")
	flagAuthKey   = flag.String("k", os.Getenv("AUTH_KEY"), "Pre-shared key (or AUTH_KEY env). Prefer env over flag.")

	flagMaxStreamsPerClient = flag.Int("max-streams", 256, "Max concurrent streams per client")
	flagStreamRatePerSec    = flag.Float64("stream-rate", 50, "New streams/sec per client")
	flagStreamRateBurst     = flag.Int("stream-burst", 100, "Stream burst per client")
	flagStreamIdle          = flag.Duration("stream-idle", 5*time.Minute, "Idle timeout per stream")
	flagDialTimeout         = flag.Duration("dial-timeout", 15*time.Second, "Dial timeout to upstream/dst")

	flagAuthRatePerSec = flag.Float64("auth-rate", 5, "Auth attempts/sec per source IP")
	flagAuthRateBurst  = flag.Int("auth-burst", 10, "Auth attempts burst per source IP")
	flagAllowedOrigins = flag.String("allowed-origins", "", "Comma-separated allowed Origin headers; empty = no Origin only (native clients)")
)

// ----------------- protocol constants -----------------
const (
	protoMagic   uint16 = 0xD0E1
	protoVersion byte   = 0x01

	streamForward byte = 0x01 // server -> client -> Internet
	streamReverse byte = 0x02 // client -> server -> external user

	maxTargetLen      = 512
	clientIDMaxLen    = 64
	headerReadTimeout = 15 * time.Second
)

var clientIDRegex = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z0-9]+)+$`)

// writeStreamHeader: 2 bytes magic + 1 byte version + 1 byte type + uint16 BE len + target.
func writeStreamHeader(w io.Writer, streamType byte, target string) error {
	if len(target) > maxTargetLen {
		return errors.New("target too long")
	}
	buf := make([]byte, 2+1+1+2+len(target))
	buf[0] = byte(protoMagic >> 8)
	buf[1] = byte(protoMagic & 0xFF)
	buf[2] = protoVersion
	buf[3] = streamType
	buf[4] = byte(len(target) >> 8)
	buf[5] = byte(len(target))
	copy(buf[6:], target)
	_, err := w.Write(buf)
	return err
}

func readStreamHeader(r io.Reader) (byte, string, error) {
	var prefix [6]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return 0, "", err
	}
	if magic := uint16(prefix[0])<<8 | uint16(prefix[1]); magic != protoMagic {
		return 0, "", errors.New("bad magic")
	}
	if prefix[2] != protoVersion {
		return 0, "", errors.New("unsupported proto version")
	}
	streamType := prefix[3]
	n := int(prefix[4])<<8 | int(prefix[5])
	if n == 0 {
		return streamType, "", nil
	}
	if n > maxTargetLen {
		return 0, "", errors.New("target length exceeds max")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, "", err
	}
	return streamType, string(buf), nil
}

// ----------------- auth helpers -----------------
var authKeyHash [32]byte

func initAuthKeyHash(key string) {
	authKeyHash = sha256.Sum256([]byte(key))
}

// constantTimeAuthEqual: hằng-thời-gian.
func constantTimeAuthEqual(candidate string) bool {
	cand := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(cand[:], authKeyHash[:]) == 1
}

// ----------------- per-IP rate limiter (auth) -----------------
type ipLimiter struct {
	mu sync.Mutex
	m  map[string]*rate.Limiter
	r  rate.Limit
	b  int
}

func newIPLimiter(r rate.Limit, b int) *ipLimiter {
	return &ipLimiter{m: make(map[string]*rate.Limiter), r: r, b: b}
}

func (l *ipLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.m[ip]
	if !ok {
		lim = rate.NewLimiter(l.r, l.b)
		l.m[ip] = lim
	}
	return lim.Allow()
}

func (l *ipLimiter) gc(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.mu.Lock()
			for ip, lim := range l.m {
				// idle limiter có token đầy => bỏ
				if lim.Tokens() >= float64(l.b) {
					delete(l.m, ip)
				}
			}
			l.mu.Unlock()
		}
	}
}

var authIPLimiter *ipLimiter

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ----------------- session/registry -----------------
type session struct {
	id       string
	clientID string
	mux      *yamux.Session
	limiter  *rate.Limiter
	active   atomic.Int64
	maxAct   int64
}

// reserve: tăng active có check max, rollback nếu vượt.
func (s *session) reserve() bool {
	for {
		cur := s.active.Load()
		if cur >= s.maxAct {
			return false
		}
		if s.active.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (s *session) release() { s.active.Add(-1) }

type registry struct {
	mu sync.RWMutex
	m  map[string]*session
}

func newRegistry() *registry { return &registry{m: make(map[string]*session)} }

func (r *registry) add(s *session) {
	r.mu.Lock()
	if prev, ok := r.m[s.clientID]; ok && prev != nil && prev != s {
		_ = prev.mux.Close()
	}
	r.m[s.clientID] = s
	r.mu.Unlock()
}

func (r *registry) remove(s *session) {
	r.mu.Lock()
	if cur, ok := r.m[s.clientID]; ok && cur == s {
		delete(r.m, s.clientID)
	}
	r.mu.Unlock()
}

func (r *registry) get(clientID string) *session {
	r.mu.RLock()
	s := r.m[clientID]
	r.mu.RUnlock()
	if s == nil || s.mux.IsClosed() {
		return nil
	}
	return s
}

var reg = newRegistry()

// ----------------- ws upgrader (with origin check) -----------------
var allowedOriginSet map[string]struct{}

func buildOriginSet(csv string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, o := range strings.Split(csv, ",") {
		if o = strings.TrimSpace(o); o != "" {
			set[o] = struct{}{}
		}
	}
	return set
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  64 * 1024,
	WriteBufferSize: 64 * 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// native client (non-browser) — không có Origin
			return true
		}
		if len(allowedOriginSet) == 0 {
			return false
		}
		_, ok := allowedOriginSet[origin]
		return ok
	},
}

// ----------------- main -----------------
func main() {
	flag.Parse()
	if *flagAuthKey == "" {
		log.Fatalf("Auth key required (-k or AUTH_KEY env)")
	}
	if err := validateTLSFlags(); err != nil {
		log.Fatalf("%v", err)
	}
	if len(*flagAuthKey) < 14 {
		log.Printf("[warn] auth key < 14 chars; recommended ≥ 32 random chars")
	}
	initAuthKeyHash(*flagAuthKey)
	allowedOriginSet = buildOriginSet(*flagAllowedOrigins)
	authIPLimiter = newIPLimiter(rate.Limit(*flagAuthRatePerSec), *flagAuthRateBurst)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go authIPLimiter.gc(ctx, 5*time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("/mux", handleMux)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Are you fire or water?"))
	})

	wsSrv := &http.Server{
		Addr:              *flagListenWS,
		Handler:           mux,
		ReadHeaderTimeout: headerReadTimeout,
		MaxHeaderBytes:    1 << 16,
	}
	wssSrv := &http.Server{
		Addr:              *flagListenWSS,
		Handler:           mux,
		ReadHeaderTimeout: headerReadTimeout,
		MaxHeaderBytes:    1 << 16,
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	proxySrv := &http.Server{
		Addr:              *flagProxyAddr,
		Handler:           http.HandlerFunc(httpProxyHandler),
		ReadHeaderTimeout: headerReadTimeout,
		MaxHeaderBytes:    1 << 16,
	}
	proxyTLSSrv := &http.Server{
		Addr:              *flagProxyTLS,
		Handler:           http.HandlerFunc(httpProxyHandler),
		ReadHeaderTimeout: headerReadTimeout,
		MaxHeaderBytes:    1 << 16,
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	if *flagProxyAddr != "" {
		go func() {
			log.Printf("[proxy] http listening on %s", *flagProxyAddr)
			if err := proxySrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("proxy http listen: %v", err)
			}
		}()
	}

	if *flagProxyTLS != "" {
		go func() {
			log.Printf("[proxy] https listening on %s", *flagProxyTLS)
			if err := proxyTLSSrv.ListenAndServeTLS(*flagTLSCert, *flagTLSKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("proxy https listen: %v", err)
			}
		}()
	}

	if *flagListenWS != "" {
		go func() {
			log.Printf("[mux] ws listening on %s", *flagListenWS)
			if err := wsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("mux ws listen: %v", err)
			}
		}()
	}

	if *flagListenWSS != "" {
		go func() {
			log.Printf("[mux] wss listening on %s", *flagListenWSS)
			if err := wssSrv.ListenAndServeTLS(*flagTLSCert, *flagTLSKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("mux wss listen: %v", err)
			}
		}()
	}

	<-ctx.Done()
	log.Printf("[main] shutdown signal, draining...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = wsSrv.Shutdown(shutdownCtx)
	_ = wssSrv.Shutdown(shutdownCtx)
	_ = proxySrv.Shutdown(shutdownCtx)
	_ = proxyTLSSrv.Shutdown(shutdownCtx)
	log.Printf("[main] bye")
}

func validateTLSFlags() error {
	hasWSS := strings.TrimSpace(*flagListenWSS) != ""
	hasProxyTLS := strings.TrimSpace(*flagProxyTLS) != ""
	hasCert := strings.TrimSpace(*flagTLSCert) != ""
	hasKey := strings.TrimSpace(*flagTLSKey) != ""
	if !hasWSS && !hasProxyTLS && (hasCert || hasKey) {
		return errors.New("-tls-cert/-tls-key require -wss or -proxy-tls")
	}
	if (hasWSS || hasProxyTLS) && (!hasCert || !hasKey) {
		return errors.New("-wss/-proxy-tls require both -tls-cert and -tls-key")
	}
	if strings.TrimSpace(*flagListenWS) == "" && !hasWSS {
		return errors.New("at least one mux listener is required (-ws or -wss)")
	}
	if strings.TrimSpace(*flagProxyAddr) == "" && !hasProxyTLS {
		return errors.New("at least one proxy listener is required (-proxy or -proxy-tls)")
	}
	return nil
}

// ----------------- /mux: client mở session -----------------
func handleMux(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !looksLikeMuxHandshake(r) {
		writeStealthNotFound(w, r)
		return
	}

	clientID := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Client-Id")))
	if !validClientID(clientID) {
		writeStealthNotFound(w, r)
		return
	}

	if !authIPLimiter.Allow(ip) {
		writeStealthNotFound(w, r)
		return
	}

	if !constantTimeAuthEqual(r.Header.Get("X-Auth-Key")) {
		log.Printf("[mux] auth fail from %s", ip)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	netConn := wsToNetConn(wsConn)

	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 20 * time.Second
	cfg.ConnectionWriteTimeout = 15 * time.Second
	cfg.MaxStreamWindowSize = 1024 * 1024
	cfg.LogOutput = io.Discard

	yam, err := yamux.Server(netConn, cfg)
	if err != nil {
		log.Printf("[mux] yamux: %v", err)
		_ = wsConn.Close()
		return
	}

	sid, err := randomID(8)
	if err != nil {
		_ = yam.Close()
		_ = wsConn.Close()
		return
	}
	s := &session{
		id:       sid,
		clientID: clientID,
		mux:      yam,
		limiter:  rate.NewLimiter(rate.Limit(*flagStreamRatePerSec), *flagStreamRateBurst),
		maxAct:   int64(*flagMaxStreamsPerClient),
	}
	reg.add(s)
	log.Printf("[mux] client=%s session=%s connected from %s", clientID, sid, ip)

	defer func() {
		reg.remove(s)
		_ = yam.Close()
		log.Printf("[mux] client=%s session=%s disconnected", clientID, sid)
	}()

	for {
		stream, err := yam.AcceptStream()
		if err != nil {
			return
		}
		go handleForwardStream(s, stream)
	}
}

func looksLikeMuxHandshake(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		websocket.IsWebSocketUpgrade(r) &&
		r.Header.Get("Sec-WebSocket-Key") != "" &&
		r.Header.Get("Sec-WebSocket-Version") == "13"
}

func validClientID(id string) bool {
	if id == "" || len(id) > clientIDMaxLen {
		return false
	}
	return clientIDRegex.MatchString(id)
}

// FORWARD: client yêu cầu server dial Internet thay (cho SOCKS5 outbound bên client).
func handleForwardStream(s *session, stream *yamux.Stream) {
	defer stream.Close()

	if !s.limiter.Allow() {
		return
	}
	if !s.reserve() {
		return
	}
	defer s.release()

	_ = stream.SetReadDeadline(time.Now().Add(headerReadTimeout))
	streamType, target, err := readStreamHeader(stream)
	if err != nil {
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	if streamType != streamForward {
		log.Printf("[forward] unexpected stream type %d", streamType)
		return
	}
	if !strings.Contains(target, ":") {
		target += ":80"
	}

	dst, err := net.DialTimeout("tcp", target, *flagDialTimeout)
	if err != nil {
		return
	}
	idle := newIdleConn(dst, *flagStreamIdle)
	streamWrap := newIdleStream(stream, *flagStreamIdle)
	bridge(streamWrap, idle)
}

// ----------------- HTTP proxy: external user -> reverse tunnel -----------------
func httpProxyHandler(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	clientID, authOK := proxyAuth(r)
	if !authOK {
		if !authIPLimiter.Allow(ip) {
			writeStealthNotFound(w, r)
			return
		}
		if shouldChallengeProxyAuth(r) {
			writeProxyAuthRequired(w)
			return
		}
		writeStealthNotFound(w, r)
		return
	}
	if !validClientID(clientID) {
		// đã pass key nhưng clientID xấu — vẫn 502 để không leak info
		http.Error(w, "no client available", http.StatusBadGateway)
		return
	}

	var dst string
	if r.Method == http.MethodConnect {
		dst = r.Host
		if !strings.Contains(dst, ":") {
			dst += ":443"
		}
	} else {
		if r.URL == nil || r.URL.Host == "" {
			http.Error(w, "absolute-form required", http.StatusBadRequest)
			return
		}
		dst = r.URL.Host
		if !strings.Contains(dst, ":") {
			dst += ":80"
		}
	}

	sess := reg.get(clientID)
	if sess == nil || !sess.reserve() {
		// thống nhất 502 — không phân biệt offline vs over-quota để tránh enumeration
		http.Error(w, "no client available", http.StatusBadGateway)
		return
	}
	released := false
	defer func() {
		if !released {
			sess.release()
		}
	}()

	if !sess.limiter.Allow() {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	clientConn, brw, err := hj.Hijack()
	if err != nil {
		return
	}

	stream, err := sess.mux.OpenStream()
	if err != nil {
		_, _ = brw.WriteString("HTTP/1.1 502 Bad Gateway\r\n\r\n")
		_ = brw.Flush()
		_ = clientConn.Close()
		return
	}

	if err := writeStreamHeader(stream, streamReverse, dst); err != nil {
		_ = stream.Close()
		_ = clientConn.Close()
		return
	}

	idle := newIdleConn(clientConn, *flagStreamIdle)
	streamWrap := newIdleStream(stream, *flagStreamIdle)

	// release reservation chỉ khi bridge xong (đảm bảo active counter chính xác)
	released = true
	go func() {
		defer sess.release()
		if r.Method == http.MethodConnect {
			_, _ = brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			if err := brw.Flush(); err != nil {
				_ = streamWrap.Close()
				_ = idle.Close()
				return
			}
			bridge(streamWrap, idle)
			return
		}
		if err := writeUpstreamRequest(streamWrap, r); err != nil {
			_ = streamWrap.Close()
			_ = idle.Close()
			return
		}
		bridge(streamWrap, &bufConn{brw: brw, conn: idle})
	}()
}

func writeStealthNotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "close")
	http.NotFound(w, r)
}

func shouldChallengeProxyAuth(r *http.Request) bool {
	if r.Method == http.MethodConnect {
		return r.Host != ""
	}
	return r.URL != nil && r.URL.IsAbs() && r.URL.Host != ""
}

func writeProxyAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="tun"`)
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusProxyAuthRequired)
}

func proxyAuth(r *http.Request) (string, bool) {
	v := r.Header.Get("Proxy-Authorization")
	if v == "" {
		return "", false
	}
	const prefix = "Basic "
	if len(v) <= len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return "", false
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[len(prefix):]))
	if err != nil {
		return "", false
	}
	parts := strings.SplitN(string(dec), ":", 2)
	if len(parts) != 2 {
		return "", false
	}
	if !constantTimeAuthEqual(parts[1]) {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(parts[0])), true
}

func writeUpstreamRequest(w io.Writer, r *http.Request) error {
	r.RequestURI = ""
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")
	bw := bufio.NewWriter(w)
	if err := r.Write(bw); err != nil {
		return err
	}
	return bw.Flush()
}

// ----------------- IO bridge + idle conn -----------------
type halfCloser interface {
	CloseWrite() error
}

type idleConn struct {
	net.Conn
	idle    time.Duration
	lastIO  atomic.Int64
	stopCh  chan struct{}
	stopped atomic.Bool
}

func newIdleConn(c net.Conn, idle time.Duration) *idleConn {
	ic := &idleConn{Conn: c, idle: idle, stopCh: make(chan struct{})}
	ic.lastIO.Store(time.Now().UnixNano())
	go ic.watch()
	return ic
}

func (ic *idleConn) Read(b []byte) (int, error) {
	n, err := ic.Conn.Read(b)
	if n > 0 {
		ic.lastIO.Store(time.Now().UnixNano())
	}
	return n, err
}

func (ic *idleConn) Write(b []byte) (int, error) {
	n, err := ic.Conn.Write(b)
	if n > 0 {
		ic.lastIO.Store(time.Now().UnixNano())
	}
	return n, err
}

func (ic *idleConn) Close() error {
	if ic.stopped.CompareAndSwap(false, true) {
		close(ic.stopCh)
	}
	return ic.Conn.Close()
}

func (ic *idleConn) watch() {
	t := time.NewTicker(ic.idle / 2)
	defer t.Stop()
	for {
		select {
		case <-ic.stopCh:
			return
		case now := <-t.C:
			if now.UnixNano()-ic.lastIO.Load() > int64(ic.idle) {
				_ = ic.Conn.Close()
				return
			}
		}
	}
}

// idleStream: idle timeout cho yamux stream (không thuộc net.Conn nhưng có Read/Write/Close + SetDeadline).
type idleStream struct {
	s       *yamux.Stream
	idle    time.Duration
	lastIO  atomic.Int64
	stopCh  chan struct{}
	stopped atomic.Bool
}

func newIdleStream(s *yamux.Stream, idle time.Duration) *idleStream {
	is := &idleStream{s: s, idle: idle, stopCh: make(chan struct{})}
	is.lastIO.Store(time.Now().UnixNano())
	go is.watch()
	return is
}

func (is *idleStream) Read(b []byte) (int, error) {
	n, err := is.s.Read(b)
	if n > 0 {
		is.lastIO.Store(time.Now().UnixNano())
	}
	return n, err
}

func (is *idleStream) Write(b []byte) (int, error) {
	n, err := is.s.Write(b)
	if n > 0 {
		is.lastIO.Store(time.Now().UnixNano())
	}
	return n, err
}

func (is *idleStream) Close() error {
	if is.stopped.CompareAndSwap(false, true) {
		close(is.stopCh)
	}
	return is.s.Close()
}

func (is *idleStream) CloseWrite() error { return is.Close() }

func (is *idleStream) watch() {
	t := time.NewTicker(is.idle / 2)
	defer t.Stop()
	for {
		select {
		case <-is.stopCh:
			return
		case now := <-t.C:
			if now.UnixNano()-is.lastIO.Load() > int64(is.idle) {
				_ = is.s.Close()
				return
			}
		}
	}
}

func bridge(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(dst, src, buf)
		if hc, ok := dst.(halfCloser); ok {
			_ = hc.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// ----------------- bufConn (cho non-CONNECT replay) -----------------
type bufConn struct {
	brw  *bufio.ReadWriter
	conn *idleConn
}

func (x *bufConn) Read(b []byte) (int, error)  { return x.brw.Read(b) }
func (x *bufConn) Write(b []byte) (int, error) { return x.conn.Write(b) }
func (x *bufConn) Close() error                { return x.conn.Close() }
func (x *bufConn) CloseWrite() error {
	if tcp, ok := x.conn.Conn.(*net.TCPConn); ok {
		return tcp.CloseWrite()
	}
	return x.conn.Close()
}

// ----------------- WebSocket -> net.Conn cho yamux -----------------
type wsNetConn struct {
	ws     *websocket.Conn
	reader io.Reader
	wmu    sync.Mutex
	closed atomic.Bool
}

func wsToNetConn(ws *websocket.Conn) net.Conn {
	ws.SetReadLimit(0)
	return &wsNetConn{ws: ws}
}

func (c *wsNetConn) Read(b []byte) (int, error) {
	for {
		if c.reader == nil {
			mt, r, err := c.ws.NextReader()
			if err != nil {
				return 0, err
			}
			if mt != websocket.BinaryMessage {
				continue
			}
			c.reader = r
		}
		n, err := c.reader.Read(b)
		if errors.Is(err, io.EOF) {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *wsNetConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsNetConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	return c.ws.Close()
}

func (c *wsNetConn) LocalAddr() net.Addr  { return c.ws.LocalAddr() }
func (c *wsNetConn) RemoteAddr() net.Addr { return c.ws.RemoteAddr() }
func (c *wsNetConn) SetDeadline(t time.Time) error {
	if err := c.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return c.ws.SetWriteDeadline(t)
}
func (c *wsNetConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *wsNetConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }

func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
