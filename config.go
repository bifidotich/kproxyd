package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// ProbeCfg — параметры проверки узлов.
type ProbeCfg struct {
	URL              string `json:"url"`
	DNS              string `json:"dns"` // DNS для проверки и для имён в SOCKS5-запросах, запрос идёт через туннель; "system" = резолвер роутера
	IntervalSec      int    `json:"interval_sec"`
	TimeoutMs        int    `json:"timeout_ms"`
	FailThreshold    int    `json:"fail_threshold"`    // столько неудач подряд -> узел считается упавшим
	RecoverThreshold int    `json:"recover_threshold"` // столько успехов подряд -> узел снова живой
	ReturnDelaySec   int    `json:"return_delay_sec"`  // сколько узел должен прожить, прежде чем на него вернутся (fallback)
}

// OutletCfg — выход (туннель Keenetic), через который можно отправлять трафик.
type OutletCfg struct {
	Name    string `json:"name"`
	Iface   string `json:"iface"`         // имя в Keenetic: Wireguard0
	Dev     string `json:"dev,omitempty"` // системное имя (nwg0); пусто = определить автоматически
	Enabled bool   `json:"enabled"`
}

// GroupCfg — группа: набор выходов + политика выбора + SOCKS5-сервер, к которому в Keenetic
// подключают «Клиент прокси» (Proxy0) и направляют в него списки доменов.
type GroupCfg struct {
	Name         string   `json:"name"`
	Mode         string   `json:"mode,omitempty"` // устарело: был режим route, kproxyd больше не меняет Keenetic
	Policy       string   `json:"policy"`         // fallback | fastest
	Members      []string `json:"members"`
	Pinned       string   `json:"pinned,omitempty"` // ручное закрепление выхода
	ToleranceMs  int      `json:"tolerance_ms"`     // для fastest: переключаться, только если выигрыш больше
	Listen       string   `json:"listen"`           // адрес SOCKS5, например 127.0.0.1:1081
	User         string   `json:"user,omitempty"`
	Password     string   `json:"password,omitempty"`
	AllDown      string   `json:"all_down"`       // reject | isp
	KillOnSwitch bool     `json:"kill_on_switch"` // рвать SOCKS5-соединения при любом переключении
	MaxConns     int      `json:"max_conns"`      // предел одновременных SOCKS5-соединений группы

	// подбор подключения для каждого сайта (sites.go)
	Sniff      bool       `json:"sniff"`       // узнавать домен по началу соединения и подбирать подключение
	Failover   string     `json:"failover"`    // off | connect (не соединилось) | tls (сервер не ответил)
	WaitMs     int        `json:"wait_ms"`     // сколько ждать ответа сервера через одно подключение
	CacheMin   int        `json:"cache_min"`   // сколько помнить выбор и неудачи
	Rules      []RuleCfg  `json:"rules"`       // домен -> подключение, важнее подбора
	Watch      []WatchCfg `json:"watch"`       // ресурсы, которые kproxyd проверяет сам (watch.go)
	WatchSec   int        `json:"watch_sec"`   // интервал этих проверок
	WatchFails int        `json:"watch_fails"` // столько неудач проверки подряд -> через подключение не работает
}

// RuleCfg — ручное правило: домен и все его поддомены идут через это подключение, пока оно живо.
type RuleCfg struct {
	Domain string `json:"domain"`
	Outlet string `json:"outlet"`
}

// WatchCfg — ресурс, который kproxyd сам проверяет через каждое подключение группы.
type WatchCfg struct {
	Target  string `json:"target"`             // домен, можно с портом и путём: example.com, example.com:8443/path
	Deep    bool   `json:"deep,omitempty"`     // полный HTTPS-запрос вместо соединения и приветствия TLS
	Expect  string `json:"expect,omitempty"`   // для deep: коды успеха, например 200-399 или 200,204
	BodyNot string `json:"body_not,omitempty"` // для deep: неудача, если в начале ответа есть этот текст
}

// defaultMaxConns — предел соединений группы по умолчанию. Соединение в худшем случае
// занимает ~100 КБ памяти, 256 соединений укладываются в ~25 МБ даже на роутере со 128 МБ.
const (
	defaultMaxConns = 256
	maxMaxConns     = 10000

	maxWatch = 10  // проверок на группу: каждая — соединение через каждое подключение
	maxRules = 200 // правил на группу
)

type WebCfg struct {
	Listen   string `json:"listen"`
	User     string `json:"user"`
	Password string `json:"password"`
}

type Config struct {
	Web         WebCfg      `json:"web"`
	AllowPublic bool        `json:"allow_public,omitempty"` // пускать в веб-интерфейс и SOCKS5 клиентов не из локальных сетей
	NDMC        string      `json:"ndmc"`
	RCI         string      `json:"rci"`
	Probe       ProbeCfg    `json:"probe"`
	Outlets     []OutletCfg `json:"outlets"`
	Groups      []GroupCfg  `json:"groups"`
}

func defaultConfig() *Config {
	return &Config{
		Web:  WebCfg{Listen: ":8088", User: "admin"},
		NDMC: "/bin/ndmc",
		RCI:  "http://127.0.0.1:79",
		Probe: ProbeCfg{
			URL:              "https://cp.cloudflare.com/generate_204",
			DNS:              "1.1.1.1:53",
			IntervalSec:      10,
			TimeoutMs:        3000,
			FailThreshold:    3,
			RecoverThreshold: 2,
			ReturnDelaySec:   60,
		},
		Outlets: []OutletCfg{},
		Groups:  []GroupCfg{},
	}
}

func (c *Config) fillDefaults() {
	d := defaultConfig()
	if c.Web.Listen == "" {
		c.Web.Listen = d.Web.Listen
	}
	if c.Web.User == "" {
		c.Web.User = d.Web.User
	}
	if c.NDMC == "" {
		c.NDMC = d.NDMC
	}
	if c.RCI == "" {
		c.RCI = d.RCI
	}
	p := &c.Probe
	if p.URL == "" {
		p.URL = d.Probe.URL
	}
	if p.DNS == "" {
		p.DNS = d.Probe.DNS
	}
	if p.IntervalSec < 2 {
		p.IntervalSec = d.Probe.IntervalSec
	}
	if p.TimeoutMs < 200 {
		p.TimeoutMs = d.Probe.TimeoutMs
	}
	if p.FailThreshold < 1 {
		p.FailThreshold = d.Probe.FailThreshold
	}
	if p.RecoverThreshold < 1 {
		p.RecoverThreshold = d.Probe.RecoverThreshold
	}
	if p.ReturnDelaySec < 0 {
		p.ReturnDelaySec = 0
	}
	if c.Outlets == nil {
		c.Outlets = []OutletCfg{}
	}
	if c.Groups == nil {
		c.Groups = []GroupCfg{}
	}
	for i := range c.Groups {
		g := &c.Groups[i]
		if g.Mode == "proxy" {
			g.Mode = "" // единственный оставшийся режим, в конфиге не храним
		}
		if g.Policy == "" {
			g.Policy = "fallback"
		}
		if g.AllDown == "" {
			g.AllDown = "reject"
		}
		if g.MaxConns == 0 {
			g.MaxConns = defaultMaxConns
		}
		if g.Members == nil {
			g.Members = []string{}
		}
		if g.Failover == "" {
			g.Failover = "tls"
		}
		if g.WaitMs == 0 {
			g.WaitMs = 2500
		}
		if g.CacheMin == 0 {
			g.CacheMin = 20
		}
		if g.WatchSec == 0 {
			g.WatchSec = 120
		}
		if g.WatchFails == 0 {
			g.WatchFails = 2
		}
		if g.Rules == nil {
			g.Rules = []RuleCfg{}
		}
		for j := range g.Rules {
			g.Rules[j].Domain = normDomain(strings.TrimPrefix(strings.TrimSpace(g.Rules[j].Domain), "*."))
		}
		if g.Watch == nil {
			g.Watch = []WatchCfg{}
		}
		for j := range g.Watch {
			w := &g.Watch[j]
			w.Target = strings.TrimSpace(w.Target)
			if w.Deep && strings.TrimSpace(w.Expect) == "" {
				w.Expect = "200-399"
			}
		}
	}
}

func normDomain(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }

// validHost — доменное имя из букв, цифр, дефисов и подчёркиваний, разделённых точками.
func validHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			ch := l[i]
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
				return false
			}
		}
	}
	return true
}

// parseTarget разбирает цель проверки: домен[:порт][/путь].
func parseTarget(t string) (host, port, path string, err error) {
	if strings.Contains(t, "://") {
		return "", "", "", fmt.Errorf("укажите домен без https://")
	}
	u, err := url.Parse("https://" + t)
	if err != nil {
		return "", "", "", err
	}
	host = normDomain(u.Hostname())
	if !validHost(host) {
		return "", "", "", fmt.Errorf("недопустимый домен %q", u.Hostname())
	}
	port = u.Port()
	if port == "" {
		port = "443"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", "", "", fmt.Errorf("недопустимый порт %q", port)
	}
	return host, port, u.RequestURI(), nil
}

// parseCodes разбирает коды ответа: «200-399», «200,204», «200-299,301».
func parseCodes(s string) ([][2]int, error) {
	var res [][2]int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(strings.TrimSpace(hi))
		}
		if err1 != nil || err2 != nil || a < 100 || b > 599 || a > b {
			return nil, fmt.Errorf("коды ответа: нужно вида 200-399 или 200,204")
		}
		res = append(res, [2]int{a, b})
	}
	return res, nil
}

// Названия выходов и групп: их задаёт пользователь, держим строгий набор символов.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// safeWord — непустое имя интерфейса или устройства без пробелов, кавычек и управляющих символов
// (идёт в запрос RCI и в путь /sys/class/net).
func safeWord(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f || strings.ContainsRune(`"'\/`, r) {
			return false
		}
	}
	return true
}

func (c *Config) validate() error {
	if c.Probe.DNS != "system" {
		if _, _, err := net.SplitHostPort(c.Probe.DNS); err != nil {
			return fmt.Errorf("probe.dns: нужно host:port или \"system\"")
		}
	}
	outlets := map[string]bool{}
	for _, o := range c.Outlets {
		if o.Name == "" || o.Iface == "" {
			return fmt.Errorf("у выхода должны быть name и iface")
		}
		if !nameRe.MatchString(o.Name) {
			return fmt.Errorf("выход %q: в названии допустимы латиница, цифры, _ . -", o.Name)
		}
		if !safeWord(o.Iface) {
			return fmt.Errorf("выход %q: недопустимое имя интерфейса %q", o.Name, o.Iface)
		}
		if o.Dev != "" && !safeWord(o.Dev) {
			return fmt.Errorf("выход %q: недопустимое имя устройства %q", o.Name, o.Dev)
		}
		if outlets[o.Name] {
			return fmt.Errorf("выход %q указан дважды", o.Name)
		}
		outlets[o.Name] = true
	}
	groups := map[string]bool{}
	listens := map[string]string{}
	for _, g := range c.Groups {
		if g.Name == "" {
			return fmt.Errorf("у группы должно быть имя")
		}
		if !nameRe.MatchString(g.Name) {
			return fmt.Errorf("группа %q: в названии допустимы латиница, цифры, _ . -", g.Name)
		}
		if g.Mode != "" {
			return fmt.Errorf("группа %q: режим %q больше не поддерживается — kproxyd не меняет конфигурацию Keenetic. "+
				"Уберите \"mode\", задайте listen (SOCKS5) и в Keenetic направьте списки группы в Proxy-подключение на этот адрес", g.Name, g.Mode)
		}
		if groups[g.Name] {
			return fmt.Errorf("группа %q указана дважды", g.Name)
		}
		groups[g.Name] = true
		switch g.Policy {
		case "fallback", "fastest":
		default:
			return fmt.Errorf("группа %q: policy должна быть fallback или fastest", g.Name)
		}
		switch g.AllDown {
		case "reject", "isp":
		default:
			return fmt.Errorf("группа %q: all_down должен быть reject или isp", g.Name)
		}
		if g.MaxConns < 1 || g.MaxConns > maxMaxConns {
			return fmt.Errorf("группа %q: max_conns должен быть от 1 до %d", g.Name, maxMaxConns)
		}
		if len(g.Members) == 0 {
			return fmt.Errorf("группа %q: нет ни одного выхода", g.Name)
		}
		seen := map[string]bool{}
		for _, m := range g.Members {
			if !outlets[m] {
				return fmt.Errorf("группа %q: выход %q не существует", g.Name, m)
			}
			if seen[m] {
				return fmt.Errorf("группа %q: выход %q повторяется", g.Name, m)
			}
			seen[m] = true
		}
		if g.Pinned != "" && !seen[g.Pinned] {
			return fmt.Errorf("группа %q: закреплённый выход %q не входит в группу", g.Name, g.Pinned)
		}
		if _, _, err := net.SplitHostPort(g.Listen); err != nil {
			return fmt.Errorf("группа %q: неверный listen %q (нужно host:port)", g.Name, g.Listen)
		}
		if other, ok := listens[g.Listen]; ok {
			return fmt.Errorf("группы %q и %q слушают один адрес %s", other, g.Name, g.Listen)
		}
		listens[g.Listen] = g.Name
		if (g.User == "") != (g.Password == "") {
			return fmt.Errorf("группа %q: укажите и логин, и пароль SOCKS5, или ни того, ни другого", g.Name)
		}
		if len(g.User) > 255 || len(g.Password) > 255 { // предел протокола SOCKS5 (RFC 1929)
			return fmt.Errorf("группа %q: логин и пароль SOCKS5 не длиннее 255 байт", g.Name)
		}
		if err := g.validateSites(seen); err != nil {
			return fmt.Errorf("группа %q: %v", g.Name, err)
		}
	}
	return nil
}

func (g *GroupCfg) validateSites(members map[string]bool) error {
	switch g.Failover {
	case "off", "connect", "tls":
	default:
		return fmt.Errorf("failover должен быть off, connect или tls")
	}
	if g.WaitMs < 300 || g.WaitMs > 15000 {
		return fmt.Errorf("wait_ms должен быть от 300 до 15000")
	}
	if g.CacheMin < 1 || g.CacheMin > 1440 {
		return fmt.Errorf("cache_min должен быть от 1 до 1440")
	}
	if g.WatchSec < 30 || g.WatchSec > 3600 {
		return fmt.Errorf("watch_sec должен быть от 30 до 3600")
	}
	if g.WatchFails < 1 || g.WatchFails > 10 {
		return fmt.Errorf("watch_fails должен быть от 1 до 10")
	}
	if len(g.Rules) > maxRules {
		return fmt.Errorf("не больше %d правил", maxRules)
	}
	for _, r := range g.Rules {
		if !validHost(r.Domain) {
			return fmt.Errorf("правило: недопустимый домен %q", r.Domain)
		}
		if !members[r.Outlet] {
			return fmt.Errorf("правило %s: подключение %q не входит в группу", r.Domain, r.Outlet)
		}
	}
	if len(g.Watch) > maxWatch {
		return fmt.Errorf("не больше %d проверяемых ресурсов", maxWatch)
	}
	targets := map[string]bool{}
	for _, w := range g.Watch {
		if _, _, _, err := parseTarget(w.Target); err != nil {
			return fmt.Errorf("проверка %q: %v", w.Target, err)
		}
		if targets[w.Target] {
			return fmt.Errorf("проверка %q указана дважды", w.Target)
		}
		targets[w.Target] = true
		if w.Deep {
			if _, err := parseCodes(w.Expect); err != nil {
				return fmt.Errorf("проверка %q: %v", w.Target, err)
			}
		}
		if len(w.BodyNot) > 200 {
			return fmt.Errorf("проверка %q: текст заглушки не длиннее 200 символов", w.Target)
		}
	}
	return nil
}

func (c *Config) clone() *Config {
	b, _ := json.Marshal(c)
	var n Config
	_ = json.Unmarshal(b, &n)
	return &n
}

func (c *Config) outlet(name string) *OutletCfg {
	for i := range c.Outlets {
		if c.Outlets[i].Name == name {
			return &c.Outlets[i]
		}
	}
	return nil
}

func (c *Config) group(name string) *GroupCfg {
	for i := range c.Groups {
		if c.Groups[i].Name == name {
			return &c.Groups[i]
		}
	}
	return nil
}

// Store хранит конфиг и пишет его на диск атомарно.
type Store struct {
	mu   sync.RWMutex
	path string
	cfg  *Config
}

func loadStore(path string) (*Store, bool, error) {
	s := &Store{path: path}
	created := false
	b, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		s.cfg = defaultConfig()
		created = true
	case err != nil:
		return nil, false, err
	default:
		var c Config
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, false, fmt.Errorf("%s: %w", path, err)
		}
		s.cfg = &c
	}
	s.cfg.fillDefaults()
	if s.cfg.Web.Password == "" {
		s.cfg.Web.Password = randToken(8)
		created = true
	}
	if err := s.cfg.validate(); err != nil {
		return nil, false, err
	}
	if created {
		if err := s.write(s.cfg); err != nil {
			return nil, false, err
		}
	}
	return s, created, nil
}

func (s *Store) Get() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.clone()
}

// Update применяет функцию к копии конфига, валидирует и сохраняет.
func (s *Store) Update(fn func(c *Config) error) (*Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.cfg.clone()
	if err := fn(n); err != nil {
		return nil, err
	}
	n.fillDefaults()
	if err := n.validate(); err != nil {
		return nil, err
	}
	if err := s.write(n); err != nil {
		return nil, err
	}
	s.cfg = n
	return n.clone(), nil
}

func (s *Store) write(c *Config) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// fsync файла и каталога: после внезапного отключения питания не должен остаться пустой конфиг
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
