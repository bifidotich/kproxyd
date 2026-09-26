package main

import (
	"container/list"
	"sort"
	"sync"
	"time"
)

// Кэш сайтов: для каждой пары «группа + сайт» — через какое подключение сайт сейчас открывается,
// где не открывается и статистика для мониторинга. Только в памяти, на флеш ничего не пишется.

const (
	siteMax       = 2000             // записей на все группы; самые давние вытесняются
	suspectWindow = 10 * time.Second // столько разных сайтов подряд не открылось через подключение —
	suspectFails  = 3                // значит, дело в туннеле: ставим его в конец очереди
	suspectFor    = time.Minute      // для всех сайтов и запускаем внеочередную проверку
	hedgeMin      = 500 * time.Millisecond
	earlyWindow   = 5 * time.Second // обрыв сервером в первые секунды при почти пустом ответе —
	earlyBytes    = 16 << 10        // неудача (так режут соединения некоторые DPI)
)

type siteOutlet struct {
	OK       int       `json:"ok"`
	Fail     int       `json:"fail"`
	LastOK   time.Time `json:"last_ok"`
	LastFail time.Time `json:"last_fail"`
	Err      string    `json:"err,omitempty"` // код последней неудачи: timeout, reset, refused, …
	RTT      float64   `json:"rtt"`           // время до первого ответа сервера, мс, сглаженное
	Src      string    `json:"src"`           // последний результат: t — из трафика, p — проверка kproxyd
	BadUntil time.Time `json:"bad_until"`     // до этого времени сайт через подключение не пробуем первым
	pfails   int       // неудачи проверок подряд
}

func (o *siteOutlet) lastOK() bool { return o.LastOK.After(o.LastFail) }

type siteEntry struct {
	group, site string
	host        string // последний полный домен
	chosen      string // подключение, через которое сайт сейчас идёт
	chosenUntil time.Time
	conns       int
	lastSeen    time.Time
	per         map[string]*siteOutlet
	el          *list.Element
}

type siteCounters struct {
	conns, hits, misses, failovers int
	hedges                         []time.Time // за последний час
}

type siteKey struct{ group, site string }

type SiteCache struct {
	mu      sync.Mutex
	m       map[siteKey]*siteEntry
	lru     *list.List // спереди — недавние
	cnt     map[string]*siteCounters
	fails   map[string][]siteFail // неудачи по подключениям за suspectWindow
	suspect map[string]time.Time
}

type siteFail struct {
	t    time.Time
	site string
}

func newSiteCache() *SiteCache {
	return &SiteCache{
		m:       map[siteKey]*siteEntry{},
		lru:     list.New(),
		cnt:     map[string]*siteCounters{},
		fails:   map[string][]siteFail{},
		suspect: map[string]time.Time{},
	}
}

// entry находит или создаёт запись и отмечает её как недавнюю. Вызывать под s.mu.
func (s *SiteCache) entry(group, site, host string, now time.Time) *siteEntry {
	k := siteKey{group, site}
	e := s.m[k]
	if e == nil {
		for s.lru.Len() >= siteMax {
			old := s.lru.Remove(s.lru.Back()).(*siteEntry)
			delete(s.m, siteKey{old.group, old.site})
		}
		e = &siteEntry{group: group, site: site, per: map[string]*siteOutlet{}}
		e.el = s.lru.PushFront(e)
		s.m[k] = e
	} else {
		s.lru.MoveToFront(e.el)
	}
	if host != "" {
		e.host = host
	}
	return e
}

func (s *SiteCache) counters(group string) *siteCounters {
	c := s.cnt[group]
	if c == nil {
		c = &siteCounters{}
		s.cnt[group] = c
	}
	return c
}

// siteHint — что кэш знает о сайте к началу соединения.
type siteHint struct {
	chosen string
	bad    map[string]bool
	rtt    map[string]float64
}

// lookup отмечает новое соединение к сайту и возвращает выбранное подключение и неудачи.
func (s *SiteCache) lookup(group, site, host string, now time.Time) siteHint {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entry(group, site, host, now)
	e.conns++
	e.lastSeen = now
	h := siteHint{bad: map[string]bool{}, rtt: map[string]float64{}}
	if e.chosen != "" && now.Before(e.chosenUntil) {
		h.chosen = e.chosen
	}
	for name, o := range e.per {
		if now.Before(o.BadUntil) {
			h.bad[name] = true
		}
		if o.RTT > 0 {
			h.rtt[name] = o.RTT
		}
	}
	for name, until := range s.suspect {
		if now.Before(until) {
			h.bad[name] = true
		} else {
			delete(s.suspect, name)
		}
	}
	c := s.counters(group)
	c.conns++
	if h.chosen != "" {
		c.hits++
	} else {
		c.misses++
	}
	return h
}

func (s *SiteCache) hedged(group string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.counters(group)
	c.hedges = append(c.hedges, now)
	trimHour(c, now)
}

func trimHour(c *siteCounters, now time.Time) {
	i := 0
	for i < len(c.hedges) && (now.Sub(c.hedges[i]) > time.Hour || len(c.hedges)-i > 5000) {
		i++
	}
	c.hedges = c.hedges[i:]
}

// success — сайт открылся через подключение. Из трафика (src "t") это ещё и выбор на ttl.
func (s *SiteCache) success(group, site, outlet, src string, rtt time.Duration, ttl time.Duration, failover bool) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entry(group, site, "", now)
	o := e.outlet(outlet)
	o.OK++
	o.LastOK = now
	o.Src = src
	ms := float64(rtt.Milliseconds())
	if ms < 1 {
		ms = 1
	}
	if o.RTT == 0 {
		o.RTT = ms
	} else {
		o.RTT = o.RTT*0.7 + ms*0.3
	}
	if src == "t" {
		o.BadUntil = time.Time{}
		e.chosen, e.chosenUntil = outlet, now.Add(ttl)
		delete(s.suspect, outlet)
		delete(s.fails, outlet)
		if failover {
			s.counters(group).failovers++
		}
	} else {
		o.pfails = 0
	}
}

// failure — сайт не открылся через подключение. mark: запомнить неудачу, чтобы следующие
// соединения шли сначала через другие подключения (не ставим, если сайт не открылся нигде —
// тогда виноват он сам). Возвращает true, если подключение только что стало подозрительным.
func (s *SiteCache) failure(group, site, outlet, src, code string, mark bool, ttl time.Duration, probeFails int) (suspect bool) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entry(group, site, "", now)
	o := e.outlet(outlet)
	o.Fail++
	o.LastFail = now
	o.Err = code
	o.Src = src
	if src == "p" {
		o.pfails++
		if o.pfails < probeFails {
			return false
		}
	}
	if !mark {
		return false
	}
	o.BadUntil = now.Add(ttl)
	if e.chosen == outlet {
		e.chosen = ""
	}
	if src != "t" {
		return false
	}
	// много разных сайтов не открылось через одно подключение подряд — похоже, лёг туннель
	fl := s.fails[outlet][:0]
	for _, f := range s.fails[outlet] {
		if now.Sub(f.t) < suspectWindow && f.site != site {
			fl = append(fl, f)
		}
	}
	fl = append(fl, siteFail{now, site})
	s.fails[outlet] = fl
	if len(fl) >= suspectFails && now.After(s.suspect[outlet]) {
		s.suspect[outlet] = now.Add(suspectFor)
		delete(s.fails, outlet)
		return true
	}
	return false
}

func (e *siteEntry) outlet(name string) *siteOutlet {
	o := e.per[name]
	if o == nil {
		o = &siteOutlet{}
		e.per[name] = o
	}
	return o
}

// dropOutlet — подключение упало: сайты, которые шли через него, выбираются заново.
func (s *SiteCache) dropOutlet(outlet string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.m {
		if e.chosen == outlet {
			e.chosen = ""
		}
	}
	delete(s.suspect, outlet)
	delete(s.fails, outlet)
}

// retain убирает группы и подключения, которых больше нет в конфиге.
func (s *SiteCache) retain(members map[string]map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.m {
		mem, ok := members[k.group]
		if !ok {
			s.lru.Remove(e.el)
			delete(s.m, k)
			continue
		}
		for name := range e.per {
			if !mem[name] {
				delete(e.per, name)
			}
		}
		if !mem[e.chosen] {
			e.chosen = ""
		}
	}
	for g := range s.cnt {
		if _, ok := members[g]; !ok {
			delete(s.cnt, g)
		}
	}
}

func (s *SiteCache) reset(group, site string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.m[siteKey{group, site}]
	if e == nil {
		return false
	}
	s.lru.Remove(e.el)
	delete(s.m, siteKey{group, site})
	return true
}

// ---------- мониторинг ----------

type SiteCell struct {
	State    string    `json:"state"` // ok | fail | none
	Err      string    `json:"err,omitempty"`
	RTT      int       `json:"rtt,omitempty"`
	Src      string    `json:"src,omitempty"`
	At       time.Time `json:"at"`
	OK       int       `json:"ok"`
	Fail     int       `json:"fail"`
	Chosen   bool      `json:"chosen,omitempty"`
	Bad      bool      `json:"bad,omitempty"`
	Disabled bool      `json:"disabled,omitempty"` // подключение сейчас недоступно
}

type SiteRow struct {
	Site     string              `json:"site"`
	Host     string              `json:"host,omitempty"`
	Watched  bool                `json:"watched,omitempty"`
	Target   string              `json:"target,omitempty"`
	Deep     bool                `json:"deep,omitempty"`
	Conns    int                 `json:"conns"`
	LastSeen time.Time           `json:"last_seen"`
	Status   string              `json:"status"` // ok | alt | down | rule | none
	Via      string              `json:"via,omitempty"`
	Cells    map[string]SiteCell `json:"cells"`
}

type SiteStats struct {
	Conns      int `json:"conns"`
	Hits       int `json:"hits"`
	Misses     int `json:"misses"`
	Failovers  int `json:"failovers"`
	HedgesHour int `json:"hedges_hour"`
	Entries    int `json:"entries"`
	Max        int `json:"max"`
}

// siteView — то, что нужно для расчёта статусов, кроме самого кэша.
type siteView struct {
	g       *GroupCfg
	active  string
	healthy map[string]bool
}

func (v siteView) rule(host string) string {
	for _, r := range v.g.Rules {
		if hostMatch(host, r.Domain) {
			return r.Outlet
		}
	}
	return ""
}

// row строит строку мониторинга. Вызывать под s.mu; e может быть nil (ресурс ещё не проверялся).
func (v siteView) row(e *siteEntry, site string, now time.Time) SiteRow {
	r := SiteRow{Site: site, Cells: map[string]SiteCell{}, Status: "none"}
	if e != nil {
		r.Host, r.Conns, r.LastSeen = e.host, e.conns, e.lastSeen
	}
	var okList []string
	anyData := false
	for _, m := range v.g.Members {
		c := SiteCell{State: "none", Disabled: !v.healthy[m]}
		if e != nil {
			if o := e.per[m]; o != nil && (o.OK > 0 || o.Fail > 0) {
				c.OK, c.Fail, c.Src, c.RTT = o.OK, o.Fail, o.Src, int(o.RTT+0.5)
				c.Bad = now.Before(o.BadUntil)
				if o.lastOK() {
					c.State, c.At = "ok", o.LastOK
				} else {
					c.State, c.At, c.Err = "fail", o.LastFail, o.Err
				}
			}
			c.Chosen = e.chosen == m && now.Before(e.chosenUntil)
		}
		if c.State != "none" && !c.Disabled {
			anyData = true
			if c.State == "ok" {
				okList = append(okList, m)
			}
		}
		r.Cells[m] = c
	}
	host := r.Host
	if host == "" {
		host = site
	}
	if ro := v.rule(host); ro != "" && v.healthy[ro] {
		r.Status, r.Via = "rule", ro
		if c, ok := r.Cells[ro]; ok {
			c.Chosen = true
			r.Cells[ro] = c
		}
		return r
	}
	if !anyData {
		return r
	}
	if len(okList) == 0 {
		r.Status = "down"
		return r
	}
	via := okList[0]
	if e != nil && e.chosen != "" && now.Before(e.chosenUntil) && v.healthy[e.chosen] {
		via = e.chosen
	}
	r.Via = via
	if via == v.active {
		r.Status = "ok"
	} else {
		r.Status = "alt"
	}
	return r
}

// rows — мониторинг группы: сначала проверяемые ресурсы (в порядке настройки), затем сайты
// из трафика, недавние первыми. traffic=false — только проверяемые.
func (s *SiteCache) rows(v siteView, traffic bool, limit int) (rows []SiteRow, total int, st SiteStats) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	watched := map[string]bool{}
	for _, w := range v.g.Watch {
		host, _, _, _ := parseTarget(w.Target)
		site := siteOf(host)
		if watched[site] {
			continue
		}
		watched[site] = true
		r := v.row(s.m[siteKey{v.g.Name, site}], site, now)
		r.Watched, r.Target, r.Deep = true, w.Target, w.Deep
		rows = append(rows, r)
	}
	var rest []*siteEntry
	for k, e := range s.m {
		if k.group == v.g.Name && !watched[k.site] && e.conns > 0 {
			rest = append(rest, e)
		}
	}
	total = len(rest)
	if traffic {
		sort.Slice(rest, func(i, j int) bool { return rest[i].lastSeen.After(rest[j].lastSeen) })
		for _, e := range rest {
			if len(rows)-len(watched) >= limit {
				break
			}
			rows = append(rows, v.row(e, e.site, now))
		}
	}
	c := s.counters(v.g.Name)
	trimHour(c, now)
	st = SiteStats{Conns: c.conns, Hits: c.hits, Misses: c.misses, Failovers: c.failovers,
		HedgesHour: len(c.hedges), Entries: s.lru.Len(), Max: siteMax}
	return rows, total, st
}

// SiteSummary — блок «Ресурсы» в карточке группы.
type SiteSummary struct {
	Rows  []SiteRow `json:"rows"`
	Total int       `json:"total"` // сайтов из трафика
	Alt   int       `json:"alt"`
	Down  int       `json:"down"`
}

func (s *SiteCache) summary(v siteView) *SiteSummary {
	rows, _, _ := s.rows(v, true, siteMax)
	sum := &SiteSummary{Rows: []SiteRow{}}
	problems := 0
	for _, r := range rows {
		if !r.Watched {
			sum.Total++
			switch r.Status {
			case "alt":
				sum.Alt++
			case "down":
				sum.Down++
			default:
				continue
			}
			if problems >= 3 {
				continue
			}
			problems++
		}
		sum.Rows = append(sum.Rows, r)
	}
	return sum
}
