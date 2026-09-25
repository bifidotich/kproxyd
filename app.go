package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const historyLen = 60

type OutletState struct {
	Name       string    `json:"name"`
	Iface      string    `json:"iface"`
	Dev        string    `json:"dev"`
	Enabled    bool      `json:"enabled"`
	Healthy    bool      `json:"healthy"`
	RTT        int       `json:"rtt"`  // последний замер, мс; -1 = неудача
	EWMA       float64   `json:"ewma"` // сглаженная задержка
	Fails      int       `json:"fails"`
	Succ       int       `json:"succ"`
	UpSince    time.Time `json:"up_since"`
	LastCheck  time.Time `json:"last_check"`
	LastErr    string    `json:"last_err,omitempty"`
	History    []int     `json:"history"`
	KConnected string    `json:"k_connected"` // что думает о туннеле сам Keenetic
	Handshake  string    `json:"handshake,omitempty"`
	Conns      int       `json:"conns"`
}

type GroupState struct {
	Name     string    `json:"name"`
	Active   string    `json:"active"` // имя выхода; "" = все лежат
	Since    time.Time `json:"since"`
	Reason   string    `json:"reason"`
	Conns    int       `json:"conns"`
	ListenOK bool      `json:"listen_ok"`
	ListenEr string    `json:"listen_err,omitempty"`

	// что видно в конфигурации Keenetic (только чтение): Proxy-подключения на адрес группы
	// и списки доменов, направленные в них
	ProxyIfaces []string `json:"proxy_ifaces"`
	Lists       []string `json:"lists"`
	KeeneticOK  bool     `json:"keenetic_ok"`
	KeeneticMsg string   `json:"keenetic_msg"`
}

type Event struct {
	T     time.Time `json:"t"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
}

type App struct {
	store *Store
	k     *Keenetic

	mu      sync.RWMutex
	outlets map[string]*OutletState
	groups  map[string]*GroupState
	kIfaces []KIface
	kRC     *RunningConfig
	kErr    string
	events  []Event
	socks   map[string]*SocksServer // по имени группы

	applyMu   sync.Mutex // изменения конфига применяются строго по одному
	tracker   *ConnTracker
	probeNow  chan struct{}
	inspectCh chan struct{} // перечитать конфигурацию Keenetic
}

func newApp(store *Store) *App {
	c := store.Get()
	a := &App{
		store:     store,
		k:         newKeenetic(c.NDMC, c.RCI),
		outlets:   map[string]*OutletState{},
		groups:    map[string]*GroupState{},
		socks:     map[string]*SocksServer{},
		tracker:   newConnTracker(),
		probeNow:  make(chan struct{}, 1),
		inspectCh: make(chan struct{}, 1),
	}
	a.rebuild(c)
	return a
}

func (a *App) logf(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] %s", level, msg)
	a.mu.Lock()
	a.events = append(a.events, Event{T: time.Now(), Level: level, Msg: msg})
	if len(a.events) > 300 {
		a.events = a.events[len(a.events)-300:]
	}
	a.mu.Unlock()
}

// rebuild приводит состояние в памяти в соответствие с конфигом (без потери истории замеров).
func (a *App) rebuild(c *Config) {
	a.mu.Lock()
	nOut := map[string]*OutletState{}
	for _, o := range c.Outlets {
		st := a.outlets[o.Name]
		if st == nil {
			st = &OutletState{Name: o.Name, RTT: -1, History: []int{}}
		}
		if st.Iface != o.Iface || (o.Dev != "" && st.Dev != o.Dev) {
			st.Dev = o.Dev // пусто -> определим заново при следующей проверке
		}
		st.Iface = o.Iface
		st.Enabled = o.Enabled
		if !o.Enabled {
			st.Healthy = false
		}
		nOut[o.Name] = st
	}
	a.outlets = nOut
	nGr := map[string]*GroupState{}
	for _, g := range c.Groups {
		st := a.groups[g.Name]
		if st == nil {
			st = &GroupState{Name: g.Name}
		}
		nGr[g.Name] = st
	}
	a.groups = nGr
	a.mu.Unlock()

	a.reconcileSocks(c)
	a.evaluate()
}

// ---------- SOCKS-серверы ----------

func (a *App) reconcileSocks(c *Config) {
	want := map[string]GroupCfg{}
	for _, g := range c.Groups {
		want[g.Name] = g
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for name, s := range a.socks {
		g, ok := want[name]
		if !ok || g.Listen != s.addr {
			s.Close()
			delete(a.socks, name)
			continue
		}
		s.SetAuth(g.User, g.Password)
		s.SetLimit(g.MaxConns)
	}
	for name, g := range want {
		gs := a.groups[name]
		if gs == nil {
			continue // группу уже убрал более новый rebuild
		}
		if _, ok := a.socks[name]; ok {
			gs.ListenOK, gs.ListenEr = true, ""
			continue
		}
		s, err := startSocks(a, name, g.Listen, g.User, g.Password, g.MaxConns)
		if err != nil {
			if gs.ListenEr != err.Error() { // повторные попытки идут каждый цикл проверки — не засоряем журнал
				go a.logf("error", "группа %s: не удалось открыть %s: %v", name, g.Listen, err)
			}
			gs.ListenOK, gs.ListenEr = false, err.Error()
			continue
		}
		if gs.ListenEr != "" {
			go a.logf("info", "группа %s: SOCKS5 открыт на %s", name, g.Listen)
		}
		gs.ListenOK, gs.ListenEr = true, ""
		a.socks[name] = s
	}
}

// retrySocks повторяет открытие SOCKS5-портов, которые не открылись раньше (порт был занят).
// Берёт свежий конфиг под applyMu, чтобы не откатить изменение, применяемое параллельно.
func (a *App) retrySocks() {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	c := a.store.Get()
	a.mu.RLock()
	missing := false
	for _, g := range c.Groups {
		if _, ok := a.socks[g.Name]; !ok {
			missing = true
		}
	}
	a.mu.RUnlock()
	if missing {
		a.reconcileSocks(c)
	}
}

// pick возвращает устройство, через которое группа должна отправить новое соединение.
func (a *App) pick(c *Config, group string) (dev, outlet string, ok bool) {
	g := c.group(group)
	if g == nil {
		return "", "", false
	}
	a.mu.RLock()
	gs := a.groups[group]
	var active string
	if gs != nil {
		active = gs.Active
	}
	if st := a.outlets[active]; active != "" && st != nil {
		dev = st.Dev
	}
	a.mu.RUnlock()
	if dev != "" {
		return dev, active, true
	}
	if g.AllDown == "isp" {
		return wanDev(), "isp", true
	}
	return "", "", false
}

// ---------- проверка выходов ----------

func (a *App) probeLoop(ctx context.Context) {
	for {
		a.retrySocks()
		c := a.store.Get()
		a.probeAll(c)
		t := time.NewTimer(time.Duration(c.Probe.IntervalSec) * time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-a.probeNow:
			t.Stop()
		case <-t.C:
		}
	}
}

func (a *App) probeAll(c *Config) {
	ifs, err := a.k.Interfaces()
	kstate := map[string]KIface{}
	if err == nil {
		for _, f := range ifs {
			kstate[f.ID] = f
		}
	}
	a.mu.Lock()
	if err == nil {
		a.kIfaces = ifs
	}
	a.mu.Unlock()

	var wg sync.WaitGroup
	for _, o := range c.Outlets {
		if !o.Enabled {
			continue
		}
		wg.Add(1)
		go func(o OutletCfg) {
			defer wg.Done()
			a.probeOne(c, o, kstate)
		}(o)
	}
	wg.Wait()
	a.evaluate()
}

func (a *App) probeOne(c *Config, o OutletCfg, kstate map[string]KIface) {
	a.mu.RLock()
	st := a.outlets[o.Name]
	var dev string
	if st != nil {
		dev = st.Dev
	}
	a.mu.RUnlock()
	if st == nil {
		return
	}
	if o.Dev != "" {
		dev = o.Dev
	} else if dev == "" || !devExists(dev) {
		// определяем заново: прошлое имя могло быть догадкой, сделанной, пока RCI не отвечал
		if n := a.k.SystemName(o.Iface); n != "" {
			dev = n
		}
	}

	kf, known := kstate[o.Iface]
	var rtt int = -1
	var perr error
	switch {
	case dev == "":
		perr = fmt.Errorf("не удалось определить системное имя для %s", o.Iface)
	case !devExists(dev):
		perr = fmt.Errorf("устройство %s отсутствует", dev)
	case known && kf.Connected == "no":
		perr = fmt.Errorf("Keenetic: %s не подключён", o.Iface)
	default:
		rtt, perr = httpProbe(dev, c.Probe.URL, c.Probe.DNS, time.Duration(c.Probe.TimeoutMs)*time.Millisecond)
	}

	a.mu.Lock()
	first := st.LastCheck.IsZero()
	st.Dev = dev
	st.LastCheck = time.Now()
	if known {
		st.KConnected = kf.Connected
		st.Handshake = kf.Handshake
	}
	st.RTT = rtt
	st.History = append(st.History, rtt)
	if len(st.History) > historyLen {
		st.History = st.History[len(st.History)-historyLen:]
	}
	wasHealthy := st.Healthy
	if perr != nil {
		st.LastErr = perr.Error()
		st.Fails++
		st.Succ = 0
		if st.Healthy && st.Fails >= c.Probe.FailThreshold {
			st.Healthy = false
		}
	} else {
		st.LastErr = ""
		st.Succ++
		st.Fails = 0
		if st.EWMA == 0 {
			st.EWMA = float64(rtt)
		} else {
			st.EWMA = st.EWMA*0.7 + float64(rtt)*0.3
		}
		// первый успешный замер после старта сразу делает выход рабочим, чтобы не ждать порога
		if !st.Healthy && (first || st.Succ >= c.Probe.RecoverThreshold) {
			st.Healthy = true
			st.UpSince = time.Now()
		}
	}
	changed, name, healthy, lerr := wasHealthy != st.Healthy, st.Name, st.Healthy, st.LastErr
	a.mu.Unlock()
	if changed {
		if healthy {
			a.logf("info", "выход %s доступен", name)
		} else {
			a.logf("warn", "выход %s недоступен: %s", name, lerr)
		}
	}
}

// tunnelDialer — dialer, привязанный к устройству dev. Имена резолвятся DNS-сервером dns
// тоже через это устройство: ответ не зависит от DNS роутера/провайдера (подмена, блокировки)
// и соответствует выходу туннеля. dns == "system" — обычный резолвер роутера.
func tunnelDialer(dev, dns string, timeout time.Duration) *net.Dialer {
	d := bindDialer(dev, timeout)
	if dns != "system" {
		rd := bindDialer(dev, timeout)
		d.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return rd.DialContext(ctx, network, dns)
			},
		}
	}
	return d
}

// httpProbe делает HTTP-запрос через устройство туннеля (и DNS тоже через него: иначе сбой
// DNS роутера разом «уронил» бы все выходы). Живым выход считается только при ответе 2xx:
// редирект или 4xx означают, что ответил не целевой сервер (портал авторизации, заглушка).
// Сертификат не проверяется намеренно: это проверка живости канала, а не доверия к сайту,
// и на роутере часто нет системного набора корневых сертификатов.
func httpProbe(dev, rawURL, dns string, timeout time.Duration) (int, error) {
	d := tunnelDialer(dev, dns, timeout)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp4", addr)
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	resp, err := cl.Get(rawURL)
	if err != nil {
		return -1, err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return -1, fmt.Errorf("HTTP %d вместо 2xx", resp.StatusCode)
	}
	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}

func bindDialer(dev string, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	if dev != "" {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) { serr = syscall.BindToDevice(int(fd), dev) }); err != nil {
				return err
			}
			return serr
		}
	}
	return d
}

// wanDev — устройство маршрута по умолчанию (для режима «все выходы лежат -> через провайдера»).
// Явная привязка нужна, чтобы соединение не ушло по DNS-маршруту обратно в Proxy-интерфейс.
func wanDev() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	best, bestMetric := "", int(^uint(0)>>1)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		x := strings.Fields(sc.Text())
		if len(x) < 8 || x[1] != "00000000" || x[7] != "00000000" {
			continue
		}
		m, _ := strconv.Atoi(x[6])
		if m < bestMetric {
			best, bestMetric = x[0], m
		}
	}
	return best
}

// ---------- выбор выхода в группах ----------

func (a *App) evaluate() {
	c := a.store.Get()
	now := time.Now()
	type change struct {
		group, from, to, reason string
		kill                    bool
	}
	var changes []change

	a.mu.Lock()
	for _, g := range c.Groups {
		gs := a.groups[g.Name]
		if gs == nil {
			continue
		}
		next, reason := a.choose(c, g, gs.Active, now)
		if next != gs.Active {
			old := gs.Active
			oldDown := old != "" && (a.outlets[old] == nil || !a.outlets[old].Healthy)
			changes = append(changes, change{g.Name, old, next, reason, g.KillOnSwitch || oldDown})
			gs.Active, gs.Since, gs.Reason = next, now, reason
		} else if reason != "" {
			gs.Reason = reason
		}
	}
	// счётчики соединений
	for _, st := range a.outlets {
		st.Conns = 0
	}
	for _, gs := range a.groups {
		gs.Conns = 0
	}
	for _, tc := range a.tracker.Snapshot() {
		if st := a.outlets[tc.outlet]; st != nil {
			st.Conns++
		}
		if gs := a.groups[tc.group]; gs != nil {
			gs.Conns++
		}
	}
	a.mu.Unlock()

	for _, ch := range changes {
		to := ch.to
		if to == "" {
			to = "нет доступных выходов"
		}
		from := ch.from
		if from == "" {
			from = "—"
		}
		a.logf("info", "группа %s: %s ⇒ %s (%s)", ch.group, from, to, ch.reason)
		if ch.kill && ch.from != "" {
			if n := a.tracker.CloseWhere(ch.group, ch.from); n > 0 {
				a.logf("info", "группа %s: закрыто %d соединений через %s", ch.group, n, ch.from)
			}
		}
	}
}

// choose — политика выбора. Вызывается под a.mu.
func (a *App) choose(c *Config, g GroupCfg, current string, now time.Time) (string, string) {
	healthy := func(n string) bool {
		st := a.outlets[n]
		return st != nil && st.Enabled && st.Healthy && st.Dev != ""
	}
	if g.Pinned != "" {
		if healthy(g.Pinned) {
			return g.Pinned, "закреплён вручную"
		}
		// закреплённый упал — не держимся за мёртвый, работаем по политике
	}
	var cands []string
	for _, m := range g.Members {
		if healthy(m) {
			cands = append(cands, m)
		}
	}
	if len(cands) == 0 {
		return "", "все выходы группы недоступны"
	}
	switch g.Policy {
	case "fastest":
		sort.SliceStable(cands, func(i, j int) bool {
			return a.outlets[cands[i]].EWMA < a.outlets[cands[j]].EWMA
		})
		best := cands[0]
		if healthy(current) && current != best {
			if a.outlets[current].EWMA-a.outlets[best].EWMA < float64(g.ToleranceMs) {
				return current, "разница задержек меньше порога"
			}
		}
		return best, fmt.Sprintf("минимальная задержка %.0f мс", a.outlets[best].EWMA)
	default: // fallback
		retDelay := time.Duration(c.Probe.ReturnDelaySec) * time.Second
		for _, m := range cands {
			if m == current {
				return m, "по приоритету"
			}
			// возвращаемся на более приоритетный узел только после того, как он проработал return_delay
			if !healthy(current) || now.Sub(a.outlets[m].UpSince) >= retDelay {
				return m, "по приоритету"
			}
		}
		return cands[0], "по приоритету"
	}
}

// ---------- конфигурация Keenetic (только чтение) ----------
//
// Keenetic настраивает пользователь: «Клиент прокси» (Proxy0) на SOCKS5-адрес группы
// и DNS-маршруты списков доменов в этот интерфейс. kproxyd конфигурацию не меняет —
// периодически читает её и подсказывает, что настроено не так.

func (a *App) requestInspect() {
	select {
	case a.inspectCh <- struct{}{}:
	default:
	}
}

func (a *App) inspectLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		a.inspect()
		select {
		case <-ctx.Done():
			return
		case <-a.inspectCh:
		case <-t.C:
		}
	}
}

func (a *App) inspect() {
	c := a.store.Get()
	rc, err := a.k.ReadConfig()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		if a.kErr != err.Error() {
			go a.logf("error", "чтение конфигурации Keenetic: %v", err)
		}
		a.kErr = err.Error()
		return
	}
	a.kRC, a.kErr = rc, ""
	for _, g := range c.Groups {
		if gs := a.groups[g.Name]; gs != nil {
			gs.ProxyIfaces, gs.Lists, gs.KeeneticOK, gs.KeeneticMsg = checkKeenetic(g, rc)
		}
	}
}

// checkKeenetic ищет в конфигурации Keenetic Proxy-подключения на SOCKS5-адрес группы
// и списки доменов, направленные в них.
func checkKeenetic(g GroupCfg, rc *RunningConfig) (ifaces, lists []string, ok bool, msg string) {
	lhost, lport, _ := net.SplitHostPort(g.Listen)
	anyHost := lhost == "" || net.ParseIP(lhost) != nil && net.ParseIP(lhost).IsUnspecified()
	var wrongProto []string
	for id, p := range rc.Proxies {
		host, port, err := net.SplitHostPort(p.Upstream)
		if err != nil || port != lport || !(anyHost || host == lhost) {
			continue
		}
		if p.Protocol != "" && p.Protocol != "socks5" {
			wrongProto = append(wrongProto, id+" ("+p.Protocol+")")
			continue
		}
		ifaces = append(ifaces, id)
	}
	sort.Strings(ifaces)
	on := map[string]bool{}
	for _, i := range ifaces {
		on[i] = true
	}
	var noReject []string
	for _, r := range rc.Routes {
		if on[r.Iface] {
			lists = append(lists, r.List)
			if !r.Reject {
				noReject = append(noReject, r.List)
			}
		}
	}
	sort.Strings(lists)
	sort.Strings(noReject)

	addr := g.Listen
	if anyHost {
		addr = net.JoinHostPort("127.0.0.1", lport)
	}
	switch {
	case len(wrongProto) > 0 && len(ifaces) == 0:
		return nil, nil, false, "подключение " + strings.Join(wrongProto, ", ") + " смотрит на " + addr + ", но протокол должен быть SOCKS5"
	case len(ifaces) == 0:
		return nil, nil, false, "в Keenetic нет подключения «Клиент прокси» (SOCKS5) на " + addr + " — создайте его"
	case len(lists) == 0:
		return ifaces, nil, false, "в " + strings.Join(ifaces, ", ") + " не направлен ни один список доменов — добавьте маршрут в Keenetic"
	}
	msg = strings.Join(ifaces, ", ") + " → " + addr
	if len(noReject) > 0 {
		msg += "; без «reject» у " + strings.Join(noReject, ", ") + ": если kproxyd остановится, эти домены пойдут через провайдера"
	}
	return ifaces, lists, true, msg
}

// applyConfig вызывается после изменения конфига через веб. Вызывающий держит a.applyMu.
func (a *App) applyConfig(n *Config) {
	a.rebuild(n)
	a.requestInspect()
	select {
	case a.probeNow <- struct{}{}:
	default:
	}
}
