package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Проверка ресурсов: kproxyd сам проверяет ресурсы группы через каждое её подключение,
// даже когда ими никто не пользуется. Лёгкая проверка — соединение и приветствие TLS
// (шифрования на роутере нет), глубокая — полный HTTPS-запрос.

const watchParallel = 4 // одновременных проверок

func (a *App) watchLoop(ctx context.Context) {
	next := map[string]time.Time{}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		c := a.store.Get()
		now := time.Now()
		for i := range c.Groups {
			g := &c.Groups[i]
			if len(g.Watch) == 0 {
				delete(next, g.Name)
				continue
			}
			n, ok := next[g.Name]
			if !ok {
				// после запуска сначала дожидаемся проверки самих подключений
				next[g.Name] = now.Add(15 * time.Second)
				continue
			}
			if now.Before(n) {
				continue
			}
			next[g.Name] = now.Add(time.Duration(g.WatchSec) * time.Second)
			a.watchGroup(c, g)
		}
		select {
		case <-ctx.Done():
			return
		case name := <-a.watchNow:
			next[name] = time.Time{}
		case <-t.C:
		}
	}
}

func (a *App) watchSoon(group string) {
	select {
	case a.watchNow <- group:
	default:
	}
}

type watchRes struct {
	outlet string
	rtt    time.Duration
	err    string
}

func (a *App) watchGroup(c *Config, g *GroupCfg) {
	type out struct{ name, dev string }
	var outs []out
	a.mu.RLock()
	for _, m := range g.Members {
		if st := a.outlets[m]; st != nil && st.Enabled && st.Healthy && st.Dev != "" {
			outs = append(outs, out{m, st.Dev})
		}
	}
	a.mu.RUnlock()
	if len(outs) == 0 {
		return
	}
	timeout := 2 * time.Duration(g.WaitMs) * time.Millisecond
	if timeout < 3*time.Second {
		timeout = 3 * time.Second
	}
	if timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	ttl := time.Duration(g.CacheMin) * time.Minute

	sem := make(chan struct{}, watchParallel)
	var wg sync.WaitGroup
	results := make([][]watchRes, len(g.Watch))
	for i, w := range g.Watch {
		results[i] = make([]watchRes, len(outs))
		for j, o := range outs {
			wg.Add(1)
			go func(i, j int, w WatchCfg, o out) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				var r watchRes
				if w.Deep {
					r.rtt, r.err = deepCheck(o.dev, c.Probe.DNS, w, timeout)
				} else {
					r.rtt, r.err = lightCheck(o.dev, c.Probe.DNS, w.Target, timeout)
				}
				r.outlet = o.name
				results[i][j] = r
			}(i, j, w, o)
		}
	}
	wg.Wait()

	for i, w := range g.Watch {
		host, _, _, _ := parseTarget(w.Target)
		site := siteOf(host)
		allFail := true
		for _, r := range results[i] {
			if r.err == "" {
				allFail = false
			}
		}
		for _, r := range results[i] {
			if r.err == "" {
				a.sites.success(g.Name, site, r.outlet, "p", r.rtt, ttl, false)
			} else {
				// не открылось ни через одно подключение — виноват ресурс, туннели не отмечаем
				a.sites.failure(g.Name, site, r.outlet, "p", r.err, !allFail, ttl, g.WatchFails)
			}
		}
	}
}

// lightCheck: соединение через подключение, ClientHello с доменом и ожидание ответа сервера.
// Ловит блокировки по адресу и по домену (SNI); на роутере не шифрует ничего.
func lightCheck(dev, dns, target string, timeout time.Duration) (time.Duration, string) {
	host, port, _, err := parseTarget(target)
	if err != nil {
		return 0, "error"
	}
	hello, err := helloFor(host)
	if err != nil {
		return 0, "error"
	}
	d := tunnelDialer(dev, dns, timeout)
	guardDst(d)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	rc, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(host, port))
	if err != nil {
		return 0, failCode(err)
	}
	defer rc.Close()
	_ = rc.SetDeadline(start.Add(timeout))
	if _, err := rc.Write(hello); err != nil {
		return 0, failCode(err)
	}
	var b [1]byte
	if _, err := io.ReadFull(rc, b[:]); err != nil {
		return 0, failCode(err)
	}
	switch b[0] {
	case 0x16: // ServerHello
		return time.Since(start), ""
	case 0x15: // сервер отказал в рукопожатии — для обычного сайта так отвечает фильтр
		return 0, "alert"
	}
	return 0, "proto"
}

// deepCheck — полный HTTPS-запрос: код ответа и отсутствие текста заглушки.
func deepCheck(dev, dns string, w WatchCfg, timeout time.Duration) (time.Duration, string) {
	codes, err := parseCodes(w.Expect)
	if err != nil {
		return 0, "error"
	}
	d := tunnelDialer(dev, dns, timeout)
	guardDst(d)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp4", addr)
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // см. httpProbe
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest("GET", "https://"+w.Target, nil)
	if err != nil {
		return 0, "error"
	}
	// сайты отвечают ботам иначе, чем браузеру, а проверять нужно то, что увидит браузер
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	start := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		return 0, failCode(err)
	}
	defer resp.Body.Close()
	rtt := time.Since(start)
	ok := false
	for _, r := range codes {
		if resp.StatusCode >= r[0] && resp.StatusCode <= r[1] {
			ok = true
		}
	}
	if !ok {
		return 0, "http:" + strconv.Itoa(resp.StatusCode)
	}
	if w.BodyNot != "" {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if bytes.Contains(bytes.ToLower(body), bytes.ToLower([]byte(w.BodyNot))) {
			return 0, "stub"
		}
	}
	return rtt, ""
}

// ClientHello для лёгкой проверки: его пишет сам crypto/tls в соединение-заглушку,
// так приветствие ничем не отличается от настоящего. Кэшируется по домену.
var hellos struct {
	mu sync.Mutex
	m  map[string][]byte
}

func helloFor(host string) ([]byte, error) {
	hellos.mu.Lock()
	defer hellos.mu.Unlock()
	if b, ok := hellos.m[host]; ok {
		return b, nil
	}
	cc := &captureConn{}
	_ = tls.Client(cc, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519}, // без постквантовых ключей: короче и дешевле
	}).Handshake()
	if cc.buf.Len() == 0 {
		return nil, errors.New("не удалось сформировать ClientHello")
	}
	if hellos.m == nil || len(hellos.m) > 64 {
		hellos.m = map[string][]byte{}
	}
	hellos.m[host] = cc.buf.Bytes()
	return hellos.m[host], nil
}

// captureConn запоминает то, что в него пишут, а чтение сразу завершает.
type captureConn struct{ buf bytes.Buffer }

func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Write(b []byte) (int, error)      { return c.buf.Write(b) }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }
