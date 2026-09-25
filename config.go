package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
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
}

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
		if g.Members == nil {
			g.Members = []string{}
		}
	}
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
