package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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
	LastErrEn  string    `json:"last_err_en,omitempty"`
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
	ReasonEn string    `json:"reason_en"`
	Conns    int       `json:"conns"`
	ListenOK bool      `json:"listen_ok"`
	ListenEr string    `json:"listen_err,omitempty"`

	// что видно в конфигурации Keenetic (только чтение): Proxy-подключения на адрес группы
	// и списки доменов, направленные в них
	ProxyIfaces []string `json:"proxy_ifaces"`
	Lists       []string `json:"lists"`
	KeeneticOK  bool     `json:"keenetic_ok"`
	KeeneticMsg string   `json:"keenetic_msg"`
	KeeneticEn  string   `json:"keenetic_msg_en"`

	Sites *SiteSummary `json:"sites,omitempty"` // блок «Ресурсы» в карточке группы
}

type Event struct {
	T     time.Time `json:"t"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
	MsgEn string    `json:"msg_en"`
}

type App struct {
	store *Store
	k     *Keenetic

	mu      sync.RWMutex
	outlets map[string]*OutletState
	groups  map[string]*GroupState
	kIfaces []KIface
	kRC     *RunningConfig
	kErr    Text
	events  []Event
	socks   map[string]*SocksServer // по имени группы

	applyMu   sync.Mutex // изменения конфига применяются строго по одному
	tracker   *ConnTracker
	sites     *SiteCache
	probeNow  chan struct{}
	watchNow  chan string   // проверить ресурсы группы сейчас
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
		sites:     newSiteCache(),
		probeNow:  make(chan struct{}, 1),
		watchNow:  make(chan string, 8),
		inspectCh: make(chan struct{}, 1),
	}
	a.rebuild(c)
	return a
}

// logf пишет событие в журнал: в файл по-русски, в веб-интерфейс на обоих языках (см. i18n.go).
func (a *App) logf(level, format string, args ...any) {
	msg := tr(format, args...)
	log.Printf("[%s] %s", level, msg.Ru)
	a.mu.Lock()
	a.events = append(a.events, Event{T: time.Now(), Level: level, Msg: msg.Ru, MsgEn: msg.En})
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

	members := map[string]map[string]bool{}
	for _, g := range c.Groups {
		members[g.Name] = map[string]bool{}
		for _, m := range g.Members {
			members[g.Name][m] = true
		}
	}
	a.sites.retain(members)

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
			// у удалённой группы никто больше не следит за выходами — её соединения закрываем сразу
			if !ok {
				if n := a.tracker.CloseGroup(name); n > 0 {
					go a.logf("info", "узел %s удалён: закрыто %s", name, sessions(n))
				}
			}
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
				go a.logf("error", "узел %s: не удалось открыть %s: %v", name, g.Listen, err)
			}
			gs.ListenOK, gs.ListenEr = false, err.Error()
			continue
		}
		if gs.ListenEr != "" {
			go a.logf("info", "узел %s: SOCKS5 открыт на %s", name, g.Listen)
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
		perr = errf("не удалось определить системное имя для %s", o.Iface)
	case !devExists(dev):
		perr = errf("устройство %s отсутствует", dev)
	case known && kf.Connected == "no":
		perr = errf("Keenetic: %s не подключено", o.Iface)
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
		et := errText(perr)
		st.LastErr, st.LastErrEn = et.Ru, et.En
		st.Fails++
		st.Succ = 0
		if st.Healthy && st.Fails >= c.Probe.FailThreshold {
			st.Healthy = false
		}
	} else {
		st.LastErr, st.LastErrEn = "", ""
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
	changed, name, healthy, lerr := wasHealthy != st.Healthy, st.Name, st.Healthy, Text{st.LastErr, st.LastErrEn}
	a.mu.Unlock()
	if changed {
		if healthy {
			a.logf("info", "подключение %s доступно", name)
		} else {
			a.sites.dropOutlet(name)
			a.logf("warn", "подключение %s недоступно: %s", name, lerr)
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
		return -1, probeError(err, rawURL, dns, timeout)
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return -1, errf("HTTP %d вместо 2xx", resp.StatusCode)
	}
	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}

// probeError переводит ошибку проверки в понятный текст. Go пишет, например,
// «lookup cp.cloudflare.com on 127.0.0.1:53: read udp …->1.1.1.1:53: i/o timeout»: 127.0.0.1 там —
// адрес из resolv.conf, хотя запрос на самом деле ушёл к DNS-серверу проверки через туннель.
func probeError(err error, rawURL, dns string, timeout time.Duration) error {
	host := rawURL
	if u, e := url.Parse(rawURL); e == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	var de *net.DNSError
	var oe *net.OpError
	var ne net.Error
	switch {
	case errors.As(err, &de) && dns == "system":
		if de.IsNotFound {
			return errf("DNS роутера: имя %s не найдено", de.Name)
		}
		if de.IsTimeout {
			return errf("DNS роутера не ответил (искали %s)", de.Name)
		}
		return errf("DNS роутера: %s", de.Err)
	case errors.As(err, &de):
		if de.IsNotFound {
			return errf("DNS-сервер %s через туннель: имя %s не найдено", dns, de.Name)
		}
		if de.IsTimeout {
			return errf("DNS-сервер %s не ответил через туннель (искали %s)", dns, de.Name)
		}
		return errf("DNS-сервер %s через туннель: %s", dns, de.Err)
	case errors.As(err, &ne) && ne.Timeout():
		return errf("%s не ответил за %d мс", host, timeout.Milliseconds())
	case errors.As(err, &oe) && oe.Err != nil:
		return errf("не удалось соединиться с %s: %s", host, oe.Err.Error())
	}
	return err
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
		group, from, to string
		reason          Text
		kill            bool
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
			gs.Active, gs.Since = next, now
		}
		if reason.Ru != "" {
			gs.Reason, gs.ReasonEn = reason.Ru, reason.En
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
	down := map[string]bool{}
	for n, st := range a.outlets {
		if !st.Enabled || !st.Healthy {
			down[n] = true
		}
	}
	a.mu.Unlock()

	for _, ch := range changes {
		to := Text{ch.to, ch.to}
		if ch.to == "" {
			to = tr("нет доступных подключений")
		}
		from := ch.from
		if from == "" {
			from = "—"
		}
		a.logf("info", "узел %s: %s ⇒ %s (%s)", ch.group, from, to, ch.reason)
		if ch.kill && ch.from != "" {
			if n := a.tracker.CloseWhere(ch.group, ch.from); n > 0 {
				a.logf("info", "узел %s: закрыто %s через %s", ch.group, sessions(n), ch.from)
			}
		}
	}

	// через упавшее или выключенное подключение могут идти и соединения, для которых его выбрал
	// подбор для сайтов, а не только активное подключение группы: рвём их все, клиенты
	// переподключатся через рабочие
	closed := map[string]int{}
	a.tracker.closeIf(func(x *tracked) bool {
		if down[x.outlet] {
			closed[x.outlet]++
			return true
		}
		return false
	})
	for n, k := range closed {
		a.logf("info", "подключение %s недоступно: закрыто %s", n, sessions(k))
	}
}

// closeStale вызывается после изменения конфига: рвёт соединения, которые идут через
// подключение, убранное из группы или выключенное, или напрямую через провайдера, когда
// группе это больше не разрешено. Иначе они жили бы до закрытия клиентом и числились
// на подключении, которого в группе уже нет.
func (a *App) closeStale(c *Config) {
	enabled := map[string]bool{}
	for _, o := range c.Outlets {
		enabled[o.Name] = o.Enabled
	}
	allowed := map[string]map[string]bool{}
	for _, g := range c.Groups {
		m := map[string]bool{}
		for _, n := range g.Members {
			m[n] = enabled[n]
		}
		m["isp"] = g.AllDown == "isp"
		allowed[g.Name] = m
	}
	type key struct{ group, outlet string }
	closed := map[key]int{}
	a.tracker.closeIf(func(x *tracked) bool {
		m, ok := allowed[x.group]
		if !ok || m[x.outlet] {
			return false // соединения удалённых групп закрывает reconcileSocks
		}
		closed[key{x.group, x.outlet}]++
		return true
	})
	for k, n := range closed {
		a.logf("info", "узел %s: %s больше не используется — закрыто %s", k.group, k.outlet, sessions(n))
	}
}

// choose — политика выбора. Вызывается под a.mu.
func (a *App) choose(c *Config, g GroupCfg, current string, now time.Time) (string, Text) {
	healthy := func(n string) bool {
		st := a.outlets[n]
		return st != nil && st.Enabled && st.Healthy && st.Dev != ""
	}
	if g.Pinned != "" {
		if healthy(g.Pinned) {
			return g.Pinned, tr("закреплено вручную")
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
		return "", tr("все подключения узла недоступны")
	}
	switch g.Policy {
	case "fastest":
		sort.SliceStable(cands, func(i, j int) bool {
			return a.outlets[cands[i]].EWMA < a.outlets[cands[j]].EWMA
		})
		best := cands[0]
		if healthy(current) && current != best {
			if a.outlets[current].EWMA-a.outlets[best].EWMA < float64(g.ToleranceMs) {
				return current, tr("разница задержек меньше порога")
			}
		}
		return best, tr("минимальная задержка %.0f мс", a.outlets[best].EWMA)
	default: // fallback
		retDelay := time.Duration(c.Probe.ReturnDelaySec) * time.Second
		for _, m := range cands {
			if m == current {
				return m, tr("по приоритету")
			}
			// возвращаемся на более приоритетное подключение только после того, как оно проработало return_delay
			if !healthy(current) || now.Sub(a.outlets[m].UpSince) >= retDelay {
				return m, tr("по приоритету")
			}
		}
		return cands[0], tr("по приоритету")
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
		et := errText(err)
		if a.kErr != et {
			go a.logf("error", "чтение конфигурации Keenetic: %v", err)
		}
		a.kErr = et
		return
	}
	a.kRC, a.kErr = rc, Text{}
	for _, g := range c.Groups {
		if gs := a.groups[g.Name]; gs != nil {
			var msg Text
			gs.ProxyIfaces, gs.Lists, gs.KeeneticOK, msg = checkKeenetic(g, rc)
			gs.KeeneticMsg, gs.KeeneticEn = msg.Ru, msg.En
		}
	}
}

// sameHost — адрес из подключения Keenetic совпадает с адресом группы. Сравниваем как IP
// (::1 и 0:0:0:0:0:0:0:1 — один адрес), а localhost считаем 127.0.0.1.
func sameHost(a, b string) bool {
	canon := func(h string) string {
		if strings.EqualFold(h, "localhost") {
			return "127.0.0.1"
		}
		if ip, err := netip.ParseAddr(h); err == nil {
			return ip.Unmap().String()
		}
		return strings.ToLower(h)
	}
	return canon(a) == canon(b)
}

// checkKeenetic ищет в конфигурации Keenetic Proxy-подключения на SOCKS5-адрес группы
// и списки доменов, направленные в них.
func checkKeenetic(g GroupCfg, rc *RunningConfig) (ifaces, lists []string, ok bool, msg Text) {
	lhost, lport, _ := net.SplitHostPort(g.Listen)
	anyHost := lhost == "" || net.ParseIP(lhost) != nil && net.ParseIP(lhost).IsUnspecified()
	var wrongProto []string
	for id, p := range rc.Proxies {
		host, port, err := net.SplitHostPort(p.Upstream)
		if err != nil || port != lport || !(anyHost || sameHost(host, lhost)) {
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
		return nil, nil, false, tr("подключение Keenetic %s смотрит на %s, но протокол должен быть SOCKS5", strings.Join(wrongProto, ", "), addr)
	case len(ifaces) == 0:
		return nil, nil, false, tr("в Keenetic нет подключения «Клиент прокси» (SOCKS5) на %s — создайте его", addr)
	case len(lists) == 0:
		return ifaces, nil, false, tr("в %s не направлен ни один список доменов — добавьте маршрут в Keenetic", strings.Join(ifaces, ", "))
	}
	msg = tr("%s → %s", strings.Join(ifaces, ", "), addr)
	if len(noReject) > 0 {
		msg = msg.plus(tr("; без «reject» у %s: если kproxyd остановится, эти домены пойдут через провайдера", strings.Join(noReject, ", ")))
	}
	return ifaces, lists, true, msg
}

// applyConfig вызывается после изменения конфига через веб. Вызывающий держит a.applyMu.
func (a *App) applyConfig(n *Config) {
	a.rebuild(n)
	a.closeStale(n)
	a.requestInspect()
	select {
	case a.probeNow <- struct{}{}:
	default:
	}
}
