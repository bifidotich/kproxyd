package main

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// SocksServer — минимальный SOCKS5 (RFC 1928, CONNECT) + логин/пароль (RFC 1929).
// UDP ASSOCIATE не реализован: клиент прокси Keenetic на практике передаёт только TCP.
type SocksServer struct {
	app   *App
	group string
	addr  string
	ln    net.Listener

	mu         sync.RWMutex
	user, pass string

	// предел одновременных соединений: считаются и те, что ещё в рукопожатии
	active     atomic.Int64
	limit      atomic.Int64
	lastRefuse time.Time // только из serve(): когда последний раз писали в журнал об отказе
}

func startSocks(app *App, group, addr, user, pass string, limit int) (*SocksServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &SocksServer{app: app, group: group, addr: addr, ln: ln, user: user, pass: pass}
	s.limit.Store(int64(limit))
	go s.serve()
	return s, nil
}

func (s *SocksServer) SetAuth(user, pass string) {
	s.mu.Lock()
	s.user, s.pass = user, pass
	s.mu.Unlock()
}

func (s *SocksServer) SetLimit(n int) { s.limit.Store(int64(n)) }

func (s *SocksServer) Close() { s.ln.Close() }

func (s *SocksServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// при пределе сразу закрываем: ждать освобождения нельзя — очередь росла бы без границ
		if lim := s.limit.Load(); s.active.Load() >= lim {
			c.Close()
			if time.Since(s.lastRefuse) > time.Minute {
				s.lastRefuse = time.Now()
				go s.app.logf("warn", "группа %s: достигнут предел одновременных соединений (%d), новые отклоняются", s.group, lim)
			}
			continue
		}
		s.active.Add(1)
		go func() {
			defer s.active.Add(-1)
			s.handle(c)
		}()
	}
}

const (
	repOK          = 0x00
	repFail        = 0x01
	repNetUnreach  = 0x03
	repHostUnreach = 0x04
	repRefused     = 0x05
	repCmdUnsupp   = 0x07
	repAddrUnsupp  = 0x08
)

func (s *SocksServer) handle(c net.Conn) {
	defer c.Close()
	cfg := s.app.store.Get()
	if !cfg.AllowPublic && !isLocalAddr(c.RemoteAddr().String()) {
		return // не даём прокси стать открытым для интернета, если он слушает 0.0.0.0
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))

	// приветствие
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	s.mu.RLock()
	user, pass := s.user, s.pass
	s.mu.RUnlock()
	want := byte(0x00)
	if user != "" {
		want = 0x02
	}
	offered := false
	for _, m := range methods {
		if m == want {
			offered = true
		}
	}
	if !offered {
		_, _ = c.Write([]byte{5, 0xFF})
		return
	}
	if _, err := c.Write([]byte{5, want}); err != nil {
		return
	}
	if want == 0x02 && !checkUserPass(c, user, pass) {
		return
	}

	// запрос
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 5 {
		return
	}
	if req[1] != 1 { // только CONNECT
		reply(c, repCmdUnsupp, nil)
		return
	}
	var host string
	network := "tcp4"
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
		network = "tcp6"
	default:
		reply(c, repAddrUnsupp, nil)
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:]))))

	dev, outlet, ok := s.app.pick(cfg, s.group)
	if !ok {
		reply(c, repNetUnreach, nil)
		return
	}
	// имя из запроса (ATYP=3) резолвим через тот же туннель; при выходе через провайдера — обычным DNS
	var d *net.Dialer
	if outlet == "isp" {
		d = bindDialer(dev, 10*time.Second)
	} else {
		d = tunnelDialer(dev, cfg.Probe.DNS, 10*time.Second)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	rc, err := d.DialContext(ctx, network, target)
	cancel()
	if err != nil {
		reply(c, dialErrCode(err), nil)
		return
	}
	defer rc.Close()
	if la, ok := rc.LocalAddr().(*net.TCPAddr); ok {
		reply(c, repOK, la)
	} else {
		reply(c, repOK, nil)
	}
	_ = c.SetDeadline(time.Time{})

	id := s.app.tracker.Add(s.group, outlet, c, rc)
	defer s.app.tracker.Remove(id)
	pipe(c, rc)
}

func checkUserPass(c net.Conn, user, pass string) bool {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 1 {
		return false
	}
	u := make([]byte, h[1])
	if _, err := io.ReadFull(c, u); err != nil {
		return false
	}
	var pl [1]byte
	if _, err := io.ReadFull(c, pl[:]); err != nil {
		return false
	}
	p := make([]byte, pl[0])
	if _, err := io.ReadFull(c, p); err != nil {
		return false
	}
	okU := subtle.ConstantTimeCompare(u, []byte(user)) == 1
	okP := subtle.ConstantTimeCompare(p, []byte(pass)) == 1
	if okU && okP {
		_, _ = c.Write([]byte{1, 0})
		return true
	}
	_, _ = c.Write([]byte{1, 1})
	return false
}

func reply(c net.Conn, code byte, a *net.TCPAddr) {
	b := []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}
	if a != nil {
		if ip4 := a.IP.To4(); ip4 != nil {
			copy(b[4:8], ip4)
			binary.BigEndian.PutUint16(b[8:10], uint16(a.Port))
		}
	}
	_, _ = c.Write(b)
}

func dialErrCode(err error) byte {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return repRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return repNetUnreach
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, context.DeadlineExceeded):
		return repHostUnreach
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return repHostUnreach
	}
	return repFail
}

// pipe копирует данные в обе стороны; на Linux io.Copy между TCP-сокетами использует splice.
// Когда одна сторона закончила передачу, её FIN передаётся дальше (CloseWrite), а вторая
// работает, сколько нужно: клиент мог отправить запрос и закрыть запись, а ответ (большой
// файл) идёт ещё долго. Мёртвого собеседника обнаружит TCP keepalive.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}
	for _, c := range []net.Conn{a, b} {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(30 * time.Second)
		}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

// ---------- учёт соединений ----------

type tracked struct {
	group, outlet string
	a, b          net.Conn
}

type ConnTracker struct {
	mu   sync.Mutex
	next uint64
	m    map[uint64]*tracked
}

func newConnTracker() *ConnTracker { return &ConnTracker{m: map[uint64]*tracked{}} }

func (t *ConnTracker) Add(group, outlet string, a, b net.Conn) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.next++
	t.m[t.next] = &tracked{group, outlet, a, b}
	return t.next
}

func (t *ConnTracker) Remove(id uint64) {
	t.mu.Lock()
	delete(t.m, id)
	t.mu.Unlock()
}

func (t *ConnTracker) Snapshot() []tracked {
	t.mu.Lock()
	defer t.mu.Unlock()
	res := make([]tracked, 0, len(t.m))
	for _, x := range t.m {
		res = append(res, *x)
	}
	return res
}

// CloseWhere рвёт соединения группы через указанный выход — клиенты переподключатся через новый.
func (t *ConnTracker) CloseWhere(group, outlet string) int {
	t.mu.Lock()
	var victims []*tracked
	for _, x := range t.m {
		if x.group == group && x.outlet == outlet {
			victims = append(victims, x)
		}
	}
	t.mu.Unlock()
	for _, x := range victims {
		x.a.Close()
		x.b.Close()
	}
	return len(victims)
}
