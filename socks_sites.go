package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sort"
	"syscall"
	"time"
)

// Подбор подключения для каждого сайта. Клиенту сразу отвечаем «соединение установлено»,
// читаем начало его данных (ClientHello или HTTP-запрос) и узнаём домен. Эти байты отправляем
// серверу через подключения по очереди, пока он не ответит: пока клиент не получил от сервера
// ни байта, повтор через другой туннель для него незаметен. Удачный выбор запоминается.

type siteCand struct {
	outlet, dev string
	rtt         float64 // обычное время первого ответа этого сайта через подключение, мс (0 — неизвестно)
}

// siteOrder — очередь подключений для сайта: правило, выбранное раньше, активное подключение
// группы, остальные по политике; подключения, где сайт недавно не открылся, и подозрительные —
// в конце.
func (a *App) siteOrder(g *GroupCfg, host, site string) []siteCand {
	h := a.sites.lookup(g.Name, site, host, time.Now())
	a.mu.RLock()
	defer a.mu.RUnlock()
	usable := func(n string) *OutletState {
		st := a.outlets[n]
		if st == nil || !st.Enabled || !st.Healthy || st.Dev == "" {
			return nil
		}
		return st
	}
	var rule string
	if host != "" {
		for _, r := range g.Rules {
			if hostMatch(host, r.Domain) {
				rule = r.Outlet
				break
			}
		}
	}
	members := append([]string(nil), g.Members...)
	if g.Policy == "fastest" {
		sort.SliceStable(members, func(i, j int) bool {
			x, y := a.outlets[members[i]], a.outlets[members[j]]
			return x != nil && y != nil && x.EWMA < y.EWMA
		})
	}
	var active string
	if gs := a.groups[g.Name]; gs != nil {
		active = gs.Active
	}
	pref := append([]string{h.chosen, g.Pinned, active}, members...)
	seen := map[string]bool{}
	var good, bad []siteCand
	add := func(n string, force bool) {
		if n == "" || seen[n] {
			return
		}
		st := usable(n)
		if st == nil {
			return
		}
		seen[n] = true
		cd := siteCand{outlet: n, dev: st.Dev, rtt: h.rtt[n]}
		if cd.rtt == 0 && st.EWMA > 0 {
			cd.rtt = st.EWMA / 2 // проверка идёт с рукопожатием TLS, первый ответ примерно вдвое быстрее
		}
		if h.bad[n] && !force {
			bad = append(bad, cd)
		} else {
			good = append(good, cd)
		}
	}
	add(rule, true) // правило важнее всего, пока подключение живо
	for _, n := range pref {
		add(n, false)
	}
	order := append(good, bad...)
	if g.Failover == "off" && len(order) > 1 {
		order = order[:1]
	}
	return order
}

type attemptRes struct {
	i     int
	rc    net.Conn
	first []byte // первый ответ сервера — отдаётся клиенту
	rtt   time.Duration
	err   string // код неудачи; "" — успех
}

// attempt подключается к цели через подключение. waitResp: отправить prefix и ждать ответа
// сервера; иначе успех — установленное соединение (prefix отправит вызывающий).
func attempt(ctx context.Context, cd siteCand, dns, network, target string, prefix []byte, waitResp bool, wait time.Duration) attemptRes {
	start := time.Now()
	d := tunnelDialer(cd.dev, dns, wait)
	guardDst(d)
	dctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	rc, err := d.DialContext(dctx, network, target)
	if err != nil {
		return attemptRes{err: failCode(err)}
	}
	if !waitResp {
		return attemptRes{rc: rc, rtt: time.Since(start)}
	}
	stop := context.AfterFunc(ctx, func() { _ = rc.SetDeadline(time.Now()) }) // отмена: победил другой
	defer stop()
	_ = rc.SetDeadline(start.Add(wait))
	if _, err := rc.Write(prefix); err != nil {
		rc.Close()
		return attemptRes{err: failCode(err)}
	}
	buf := make([]byte, 4096)
	n, err := rc.Read(buf)
	if n == 0 {
		rc.Close()
		if err == nil {
			err = io.EOF
		}
		return attemptRes{err: failCode(err)}
	}
	_ = rc.SetDeadline(time.Time{})
	return attemptRes{rc: rc, first: buf[:n], rtt: time.Since(start)}
}

// failCode — короткий код причины неудачи; интерфейс переводит его в текст.
func failCode(err error) string {
	var dnsErr *net.DNSError
	var ne net.Error
	switch {
	case errors.Is(err, errDstForbidden):
		return "forbidden"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return "reset"
	case errors.Is(err, io.EOF):
		return "closed"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "unreach"
	case errors.As(err, &dnsErr):
		return "dns"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	}
	return "error"
}

func (s *SocksServer) handleSites(c net.Conn, cfg *Config, g *GroupCfg, network, target, reqHost string) {
	a := s.app
	reply(c, repOK, nil)
	prefix, host, isTLS := sniffPrefix(c)
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if host == "" {
		host = reqHost
	}
	site := host
	if site != "" {
		site = siteOf(host)
	} else if h, _, err := net.SplitHostPort(target); err == nil {
		if ip, err := netip.ParseAddr(h); err == nil {
			site = ip.Unmap().String()
		} else {
			site = h
		}
	}

	order := a.siteOrder(g, host, site)
	if len(order) == 0 {
		if g.AllDown != "isp" {
			return
		}
		d := bindDialer(wanDev(), 10*time.Second)
		guardDst(d)
		rc, err := d.Dial(network, target)
		if err != nil {
			return
		}
		if len(prefix) > 0 {
			if _, err := rc.Write(prefix); err != nil {
				rc.Close()
				return
			}
		}
		_ = c.SetDeadline(time.Time{})
		id := a.tracker.Add(s.group, "isp", c, rc)
		defer a.tracker.Remove(id)
		pipe(c, rc)
		return
	}

	wait := time.Duration(g.WaitMs) * time.Millisecond
	ttl := time.Duration(g.CacheMin) * time.Minute
	// ответ ждём только на ClientHello: повторять через другой туннель HTTP-запрос нельзя —
	// сервер мог его уже выполнить (POST), поэтому для HTTP успех — установленное соединение
	waitResp := g.Failover == "tls" && isTLS
	hedgeAfter := func(cd siteCand) time.Duration {
		d := time.Duration(cd.rtt*3) * time.Millisecond
		if d < hedgeMin {
			d = hedgeMin
		}
		if d > wait {
			d = wait
		}
		return d
	}

	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan attemptRes, len(order))
	started, pending := 0, 0
	launch := func() {
		i := started
		started++
		pending++
		go func() {
			r := attempt(ctx, order[i], cfg.Probe.DNS, network, target, prefix, waitResp, wait)
			r.i = i
			results <- r
		}()
	}
	launch()
	hedge := time.After(hedgeAfter(order[0]))
	var win *attemptRes
	failed := map[int]string{}
loop:
	for pending > 0 {
		select {
		case r := <-results:
			pending--
			if r.err == "" {
				win = &r
				break loop
			}
			failed[r.i] = r.err
			if r.err == "forbidden" { // адрес запрещён — через любое подключение одинаково
				break loop
			}
			if started < len(order) {
				launch()
				hedge = time.After(hedgeAfter(order[started-1]))
			}
		case <-hedge:
			// подключение молчит дольше обычного — параллельно пробуем следующее
			if started < len(order) && pending < 2 {
				a.sites.hedged(g.Name, time.Now())
				launch()
				hedge = time.After(hedgeAfter(order[started-1]))
			}
		}
	}
	cancel()
	if pending > 0 { // проигравшие попытки: дождаться и закрыть
		go func(n int) {
			for ; n > 0; n-- {
				if r := <-results; r.rc != nil {
					r.rc.Close()
				}
			}
		}(pending)
	}

	if win == nil {
		// не открылось нигде: виноват сайт или адрес, а не туннели — неудачи только учитываем
		for i, code := range failed {
			a.sites.failure(g.Name, site, order[i].outlet, "t", code, false, ttl, 0)
		}
		return
	}
	for i := 0; i < started; i++ {
		code, ok := failed[i]
		if !ok {
			if i >= win.i {
				continue // победитель или запущенная позже него попытка — о подключении ничего не известно
			}
			code = "slow" // стартовала раньше победителя и не успела ответить — тоже неудача
		}
		if a.sites.failure(g.Name, site, order[i].outlet, "t", code, true, ttl, 0) {
			a.logf("warn", "группа %s: через %s подряд не открываются разные сайты — проверяю подключение", g.Name, order[i].outlet)
			a.probeSoon()
		}
	}
	outlet := order[win.i].outlet
	a.sites.success(g.Name, site, outlet, "t", win.rtt, ttl, win.i > 0)

	rc := win.rc
	if !waitResp && len(prefix) > 0 {
		if _, err := rc.Write(prefix); err != nil {
			rc.Close()
			return
		}
	}
	if len(win.first) > 0 {
		if _, err := c.Write(win.first); err != nil {
			rc.Close()
			return
		}
	}
	_ = c.SetDeadline(time.Time{})
	committed := time.Now()
	id := a.tracker.Add(s.group, outlet, c, rc)
	defer a.tracker.Remove(id)
	down, derr := pipe(c, rc)
	// сервер ответил и почти сразу оборвал соединение — так режут некоторые DPI: следующее
	// соединение к этому сайту пойдёт сначала через другое подключение
	if waitResp && errors.Is(derr, syscall.ECONNRESET) && time.Since(committed) < earlyWindow && down < earlyBytes {
		a.sites.failure(g.Name, site, outlet, "t", "early", true, ttl, 0)
	}
}

// probeSoon — внеочередная проверка подключений.
func (a *App) probeSoon() {
	select {
	case a.probeNow <- struct{}{}:
	default:
	}
}
