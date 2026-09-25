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
	SyncOK   bool      `json:"sync_ok"`
	SyncMsg  string    `json:"sync_msg"`
	ListenOK bool      `json:"listen_ok"`
	ListenEr string    `json:"listen_err,omitempty"`
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

	staleLists map[string]bool // списки, отвязанные от групп: их маршруты надо убрать
	probed     bool            // первая проверка выходов завершена; до неё маршруты route-групп не трогаем

	applyMu  sync.Mutex // изменения конфига применяются строго по одному
	tracker  *ConnTracker
	probeNow chan struct{}
	syncCh   chan bool // true = сохранить конфигурацию Keenetic после синхронизации
}

func newApp(store *Store) *App {
	c := store.Get()
	a := &App{
		store:      store,
		k:          newKeenetic(c.NDMC, c.RCI),
		outlets:    map[string]*OutletState{},
		groups:     map[string]*GroupState{},
		socks:      map[string]*SocksServer{},
		staleLists: map[string]bool{},
		tracker:    newConnTracker(),
		probeNow:   make(chan struct{}, 1),
		syncCh:     make(chan bool, 1),
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
		if g.Mode == "proxy" {
			want[g.Name] = g
		}
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
		s, err := startSocks(a, name, g.Listen, g.User, g.Password)
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
		if _, ok := a.socks[g.Name]; g.Mode == "proxy" && !ok {
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

	a.mu.Lock()
	first := !a.probed
	a.probed = true
	a.mu.Unlock()
	a.evaluate()
	if first {
		// если все выходы лежат, evaluate не увидит смены и синхронизацию не запросит
		a.requestSync(false)
	}
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
		mode                    string
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
			changes = append(changes, change{g.Name, old, next, reason, g.Mode, g.KillOnSwitch || oldDown})
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

	needSync := false
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
		if ch.mode == "route" {
			needSync = true
		}
	}
	if needSync {
		a.requestSync(false)
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

// ---------- синхронизация DNS-маршрутов Keenetic ----------

func (a *App) requestSync(save bool) {
	select {
	case a.syncCh <- save:
	default:
		if save { // уже есть запрос в очереди; гарантируем, что сохранение не потеряется
			go func() { a.syncCh <- true }()
		}
	}
}

func (a *App) syncLoop(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case save := <-a.syncCh:
			a.syncRoutes(save)
		case <-t.C:
			a.syncRoutes(false)
		}
	}
}

func (a *App) desiredRoutes(c *Config) map[string]*DNSRoute {
	want := map[string]*DNSRoute{}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, g := range c.Groups {
		reject := g.AllDown == "reject"
		for _, l := range g.Lists {
			switch g.Mode {
			case "proxy":
				if g.ProxyIface != "" {
					want[l] = &DNSRoute{List: l, Iface: g.ProxyIface, Auto: true, Reject: reject}
				}
			case "route":
				gs := a.groups[g.Name]
				if gs != nil && gs.Active != "" {
					if o := c.outlet(gs.Active); o != nil {
						want[l] = &DNSRoute{List: l, Iface: o.Iface, Auto: true, Reject: reject}
					}
				} else if reject && len(g.Members) > 0 {
					// всё лежит, но трафик к провайдеру не выпускаем: держим маршрут в основной туннель с reject
					if o := c.outlet(g.Members[0]); o != nil {
						want[l] = &DNSRoute{List: l, Iface: o.Iface, Auto: true, Reject: true}
					}
				}
				// all_down=isp и всё лежит: маршрута нет, трафик идёт по умолчанию
			}
		}
	}
	return want
}

func (a *App) syncRoutes(save bool) {
	c := a.store.Get()
	rc, err := a.k.ReadConfig()
	if err != nil {
		a.mu.Lock()
		a.kErr = err.Error()
		a.mu.Unlock()
		a.logf("error", "чтение конфигурации Keenetic: %v", err)
		return
	}
	want := a.desiredRoutes(c)
	a.mu.RLock()
	probed := a.probed
	a.mu.RUnlock()

	owned := map[string]string{} // список -> группа
	skip := map[string]bool{}    // списки, маршруты которых пока не трогаем
	for _, g := range c.Groups {
		for _, l := range g.Lists {
			owned[l] = g.Name
			// route: до первой проверки активный выход ещё неизвестен;
			// proxy без Proxy-интерфейса: группа не донастроена, маршруты оставляем как есть
			if (g.Mode == "route" && !probed) || (g.Mode == "proxy" && g.ProxyIface == "") {
				skip[l] = true
			}
		}
	}
	ourIfaces := map[string]bool{}
	for _, o := range c.Outlets {
		ourIfaces[o.Iface] = true
	}
	for _, g := range c.Groups {
		if g.ProxyIface != "" {
			ourIfaces[g.ProxyIface] = true
		}
	}

	groupErr := map[string][]string{}
	changed := false

	for list, grp := range owned {
		if _, exists := rc.Lists[list]; !exists {
			groupErr[grp] = append(groupErr[grp], "список "+list+" не найден в Keenetic")
			continue
		}
		if skip[list] {
			continue
		}
		w := want[list]
		var cur []DNSRoute
		for _, r := range rc.Routes {
			if r.List == list {
				cur = append(cur, r)
			}
		}
		if w != nil {
			exact := false
			for _, r := range cur {
				if r == *w {
					exact = true
				}
			}
			if !exact {
				if err := a.k.SetRoute(*w, hasRoute(cur, w.List, w.Iface)); err != nil {
					groupErr[grp] = append(groupErr[grp], err.Error())
					continue
				}
				changed = true
			}
		}
		for _, r := range cur {
			if w != nil && r.Iface == w.Iface {
				continue // тот же интерфейс: флаги уже обновлены повторной командой
			}
			if !ourIfaces[r.Iface] {
				// маршрут создан не нами — не удаляем, но сообщаем о конфликте
				groupErr[grp] = append(groupErr[grp], fmt.Sprintf("список %s также направлен в %s (не управляется kproxyd) — уберите маршрут вручную", list, r.Iface))
				continue
			}
			if err := a.k.RemoveRoute(r.List, r.Iface); err != nil {
				groupErr[grp] = append(groupErr[grp], err.Error())
				continue
			}
			changed = true
		}
	}

	// списки, которые отвязали от групп: убираем только маршруты в наши интерфейсы
	a.mu.Lock()
	stale := make([]string, 0, len(a.staleLists))
	for l := range a.staleLists {
		if _, still := owned[l]; !still {
			stale = append(stale, l)
		}
	}
	a.staleLists = map[string]bool{}
	a.mu.Unlock()
	for _, l := range stale {
		for _, r := range rc.Routes {
			if r.List == l && ourIfaces[r.Iface] {
				if err := a.k.RemoveRoute(r.List, r.Iface); err != nil {
					a.logf("error", "%v", err)
				} else {
					changed = true
					a.logf("info", "маршрут списка %s -> %s удалён (список отвязан)", r.List, r.Iface)
				}
			}
		}
	}

	if changed {
		if rc2, err := a.k.ReadConfig(); err == nil {
			rc = rc2
		}
	}
	if save {
		if err := a.k.SaveConfig(); err != nil {
			a.logf("error", "сохранение конфигурации Keenetic: %v", err)
		} else {
			a.logf("info", "конфигурация Keenetic сохранена")
		}
	}

	a.mu.Lock()
	a.kRC, a.kErr = rc, ""
	for _, g := range c.Groups {
		gs := a.groups[g.Name]
		if gs == nil {
			continue
		}
		if errs := groupErr[g.Name]; len(errs) > 0 {
			gs.SyncOK, gs.SyncMsg = false, strings.Join(errs, "; ")
		} else if g.Mode == "proxy" && g.ProxyIface == "" && len(g.Lists) > 0 {
			gs.SyncOK, gs.SyncMsg = false, "не указан Proxy-интерфейс Keenetic"
		} else if g.Mode == "route" && !probed && len(g.Lists) > 0 {
			gs.SyncOK, gs.SyncMsg = true, "ожидание первой проверки выходов"
		} else {
			gs.SyncOK, gs.SyncMsg = true, "маршруты в порядке"
		}
	}
	a.mu.Unlock()
	for g, errs := range groupErr {
		a.logf("error", "группа %s: %s", g, strings.Join(errs, "; "))
	}
}

// setupProxyIface направляет интерфейс клиента прокси Keenetic на SOCKS5-сервер группы.
func (a *App) setupProxyIface(g GroupCfg) error {
	host, port, err := net.SplitHostPort(g.Listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	if err := a.k.EnsureProxyIface(g.ProxyIface, host, port, g.User, g.Password, "kproxyd-"+g.Name); err != nil {
		a.logf("error", "настройка %s: %v", g.ProxyIface, err)
		return err
	}
	a.logf("info", "интерфейс %s настроен на %s:%s", g.ProxyIface, host, port)
	return nil
}

// refreshProxyIfaces обновляет уже настроенные Proxy-интерфейсы, если у группы сменились
// адрес или логин/пароль SOCKS5 — иначе Keenetic продолжит стучаться со старыми.
func (a *App) refreshProxyIfaces(old, n *Config) {
	a.mu.RLock()
	exists := map[string]bool{}
	for _, f := range a.kIfaces {
		exists[f.ID] = true
	}
	a.mu.RUnlock()
	for _, g := range n.Groups {
		og := old.group(g.Name)
		if g.Mode != "proxy" || g.ProxyIface == "" || og == nil || og.Mode != "proxy" || og.ProxyIface != g.ProxyIface {
			continue // новые привязки настраиваются кнопкой в интерфейсе
		}
		if !exists[g.ProxyIface] || (og.Listen == g.Listen && og.User == g.User && og.Password == g.Password) {
			continue
		}
		_ = a.setupProxyIface(g)
	}
}

// applyConfig вызывается после изменения конфига через веб. Вызывающий держит a.applyMu.
func (a *App) applyConfig(old, n *Config) {
	oldLists := map[string]bool{}
	for _, g := range old.Groups {
		for _, l := range g.Lists {
			oldLists[l] = true
		}
	}
	for _, g := range n.Groups {
		for _, l := range g.Lists {
			delete(oldLists, l)
		}
	}
	a.mu.Lock()
	for l := range oldLists {
		a.staleLists[l] = true
	}
	a.mu.Unlock()
	a.rebuild(n)
	a.refreshProxyIfaces(old, n)
	a.requestSync(true)
	select {
	case a.probeNow <- struct{}{}:
	default:
	}
}
