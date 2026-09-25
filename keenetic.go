package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Keenetic — доступ к прошивке ТОЛЬКО НА ЧТЕНИЕ. Конфигурацию Keenetic настраивает пользователь,
// kproxyd её не меняет.
// Состояние интерфейсов: RCI (GET-запросы к 127.0.0.1:79, без авторизации изнутри роутера).
// Running-config: ndmc -c "show ..." — любые команды, кроме show, отвергаются в Show.
type Keenetic struct {
	ndmc string
	rci  string
	mu   sync.Mutex // команды ndmc выполняем строго по одной
	hc   *http.Client
}

func newKeenetic(ndmc, rci string) *Keenetic {
	return &Keenetic{ndmc: ndmc, rci: strings.TrimRight(rci, "/"), hc: &http.Client{Timeout: 5 * time.Second}}
}

// showRe — единственная форма команд, которую kproxyd передаёт в ndmc: show и слова без спецсимволов.
var showRe = regexp.MustCompile(`^show( [A-Za-z0-9_.-]+)+$`)

// Show выполняет show-команду и возвращает текст как есть. Любую другую команду отвергает:
// kproxyd не имеет права менять конфигурацию Keenetic.
func (k *Keenetic) Show(cmd string) (string, error) {
	if !showRe.MatchString(cmd) {
		return "", fmt.Errorf("kproxyd только читает Keenetic: команда %q запрещена", cmd)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, k.ndmc, "-c", cmd).CombinedOutput()
	out := string(b)
	if err != nil {
		return out, fmt.Errorf("ndmc %q: %v: %s", cmd, err, firstLine(out))
	}
	return out, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ---------- интерфейсы ----------

type KIface struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Description string `json:"description"`
	State       string `json:"state"`
	Link        string `json:"link"`
	Connected   string `json:"connected"`
	Address     string `json:"address"`
	Handshake   string `json:"handshake,omitempty"`
}

func (k *Keenetic) rciGet(path string) (any, error) {
	resp, err := k.hc.Get(k.rci + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("RCI %s: HTTP %d", path, resp.StatusCode)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("RCI %s: %w", path, err)
	}
	return v, nil
}

func (k *Keenetic) Interfaces() ([]KIface, error) {
	v, err := k.rciGet("/rci/show/interface")
	if err != nil {
		return nil, err
	}
	var items []map[string]any
	switch t := v.(type) {
	case map[string]any:
		for key, x := range t {
			if m, ok := x.(map[string]any); ok {
				if _, has := m["id"]; !has {
					m["id"] = key
				}
				items = append(items, m)
			}
		}
	case []any:
		for _, x := range t {
			if m, ok := x.(map[string]any); ok {
				items = append(items, m)
			}
		}
	}
	res := make([]KIface, 0, len(items))
	for _, m := range items {
		f := KIface{
			ID:          str(m["id"]),
			Type:        str(m["type"]),
			Description: str(m["description"]),
			State:       str(m["state"]),
			Link:        str(m["link"]),
			Connected:   str(m["connected"]),
			Address:     str(m["address"]),
		}
		if f.ID == "" {
			f.ID = str(m["interface-name"])
		}
		if wg, ok := m["wireguard"].(map[string]any); ok {
			f.Handshake = findHandshake(wg)
		}
		res = append(res, f)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].ID < res[j].ID })
	return res, nil
}

// findHandshake ищет в описании WG любое поле со словом handshake — формат между прошивками плавает.
func findHandshake(wg map[string]any) string {
	var walk func(x any) string
	walk = func(x any) string {
		switch t := x.(type) {
		case map[string]any:
			for k, v := range t {
				if strings.Contains(strings.ToLower(k), "handshake") {
					return str(v)
				}
			}
			for _, v := range t {
				if s := walk(v); s != "" {
					return s
				}
			}
		case []any:
			for _, v := range t {
				if s := walk(v); s != "" {
					return s
				}
			}
		}
		return ""
	}
	return walk(wg)
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case bool:
		if t {
			return "yes"
		}
		return "no"
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

var wgRe = regexp.MustCompile(`^Wireguard(\d+)$`)

// SystemName возвращает имя сетевого устройства Linux для интерфейса Keenetic (Wireguard0 -> nwg0).
func (k *Keenetic) SystemName(id string) string {
	if v, err := k.rciGet("/rci/show/interface/system-name?name=" + url.QueryEscape(id)); err == nil {
		switch t := v.(type) {
		case string:
			if t != "" && devExists(t) {
				return t
			}
		case map[string]any:
			for _, key := range []string{"system-name", "name"} {
				if s := str(t[key]); s != "" && devExists(s) {
					return s
				}
			}
		}
	}
	if m := wgRe.FindStringSubmatch(id); m != nil {
		return "nwg" + m[1]
	}
	return ""
}

func devExists(dev string) bool {
	_, err := os.Stat("/sys/class/net/" + dev)
	return err == nil
}

// ---------- running-config ----------

// DNSRoute — маршрут списка доменов в интерфейс (dns-proxy route object-group СПИСОК ИНТЕРФЕЙС ...).
type DNSRoute struct {
	List   string `json:"list"`
	Iface  string `json:"iface"`
	Auto   bool   `json:"auto"`
	Reject bool   `json:"reject"`
}

// ProxyIface — интерфейс «Клиент прокси» Keenetic, как он записан в running-config.
type ProxyIface struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"` // socks5 | http
	Upstream string `json:"upstream"` // host:port
}

type RunningConfig struct {
	Routes  []DNSRoute
	Lists   map[string]int         // имя списка -> число доменов
	Proxies map[string]*ProxyIface // интерфейс -> настройки клиента прокси
}

func (k *Keenetic) ReadConfig() (*RunningConfig, error) {
	out, err := k.Show("show running-config")
	if err != nil {
		return nil, err
	}
	return parseRunningConfig(out), nil
}

func parseRunningConfig(s string) *RunningConfig {
	rc := &RunningConfig{Lists: map[string]int{}, Proxies: map[string]*ProxyIface{}}
	ctx, cur := "", ""
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimRight(raw, "\r ")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			ctx, cur = "", ""
			switch {
			case len(f) == 1 && f[0] == "dns-proxy":
				ctx = "dns-proxy"
			case len(f) >= 3 && f[0] == "object-group" && f[1] == "fqdn":
				ctx, cur = "fqdn", f[2]
				rc.Lists[cur] += 0
			case len(f) == 2 && f[0] == "interface":
				ctx, cur = "interface", f[1]
			}
			continue
		}
		switch ctx {
		case "dns-proxy":
			if len(f) >= 4 && f[0] == "route" && f[1] == "object-group" {
				r := DNSRoute{List: f[2], Iface: f[3]}
				for _, x := range f[4:] {
					switch x {
					case "auto":
						r.Auto = true
					case "reject":
						r.Reject = true
					}
				}
				rc.Routes = append(rc.Routes, r)
			}
		case "fqdn":
			if len(f) >= 2 && f[0] == "include" {
				rc.Lists[cur]++
			}
		case "interface":
			if len(f) >= 3 && f[0] == "proxy" {
				p := rc.Proxies[cur]
				if p == nil {
					p = &ProxyIface{ID: cur}
					rc.Proxies[cur] = p
				}
				switch {
				case f[1] == "protocol":
					p.Protocol = f[2]
				case f[1] == "upstream" && len(f) >= 4:
					p.Upstream = net.JoinHostPort(f[2], f[3])
				}
			}
		}
	}
	return rc
}
