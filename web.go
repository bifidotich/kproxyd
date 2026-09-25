package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"time"
)

//go:embed ui/index.html
var uiFS embed.FS

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := uiFS.ReadFile("ui/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /api/state", a.hState)
	mux.HandleFunc("PUT /api/config", a.hPutConfig)
	mux.HandleFunc("POST /api/groups/{name}/pin", a.hPin)
	mux.HandleFunc("POST /api/probe", func(w http.ResponseWriter, r *http.Request) {
		select {
		case a.probeNow <- struct{}{}:
		default:
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	// перечитать конфигурацию Keenetic (только чтение)
	mux.HandleFunc("POST /api/keenetic/refresh", func(w http.ResponseWriter, r *http.Request) {
		a.requestInspect()
		writeJSON(w, map[string]any{"ok": true})
	})
	return a.auth(mux)
}

func (a *App) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := a.store.Get()
		if !c.AllowPublic && !isLocalAddr(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(u), []byte(c.Web.User)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(c.Web.Password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="kproxyd"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// простая защита от CSRF: изменяющие запросы только с нашим заголовком
		if r.Method != http.MethodGet && r.Header.Get("X-Kproxyd") != "1" {
			http.Error(w, "missing X-Kproxyd header", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isLocalAddr — клиент из локальной сети: loopback, частные диапазоны, link-local.
// netip понимает зону IPv6 (fe80::1%br0), которую RemoteAddr отдаёт для link-local клиентов.
func isLocalAddr(remote string) bool {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
}

func (a *App) hState(w http.ResponseWriter, r *http.Request) {
	c := a.store.Get()
	c.Web.Password = "" // пароль веб-интерфейса наружу не отдаём

	a.mu.RLock()
	outs := make([]OutletState, 0, len(a.outlets))
	for _, o := range c.Outlets {
		if st := a.outlets[o.Name]; st != nil {
			x := *st
			x.History = append([]int(nil), st.History...)
			outs = append(outs, x)
		}
	}
	// пустые списки отдаём как [], а не null: интерфейс не должен ломаться, пока Keenetic не прочитан
	grs := make([]GroupState, 0, len(a.groups))
	for _, g := range c.Groups {
		if st := a.groups[g.Name]; st != nil {
			x := *st
			x.ProxyIfaces = append([]string{}, st.ProxyIfaces...)
			x.Lists = append([]string{}, st.Lists...)
			grs = append(grs, x)
		}
	}
	kifs := append([]KIface{}, a.kIfaces...)
	lists := []map[string]any{}
	routes := []DNSRoute{}
	if a.kRC != nil {
		for name, n := range a.kRC.Lists {
			lists = append(lists, map[string]any{"name": name, "domains": n})
		}
		routes = append(routes, a.kRC.Routes...)
	}
	kerr := a.kErr
	evs := append([]Event{}, a.events...)
	a.mu.RUnlock()

	sort.Slice(lists, func(i, j int) bool { return lists[i]["name"].(string) < lists[j]["name"].(string) })
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}
	writeJSON(w, map[string]any{
		"now":        time.Now(),
		"config":     c,
		"outlets":    outs,
		"groups":     grs,
		"k_ifaces":   kifs,
		"k_lists":    lists,
		"k_routes":   routes,
		"k_error":    kerr,
		"events":     evs,
		"wan_dev":    wanDev(),
		"version":    version,
		"started_at": startedAt,
	})
}

func (a *App) hPutConfig(w http.ResponseWriter, r *http.Request) {
	var in Config
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, 400, err)
		return
	}
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	var old *Config
	n, err := a.store.Update(func(c *Config) error {
		old = c.clone() // берём под блокировкой хранилища, чтобы не разойтись с параллельным изменением
		pw := c.Web.Password
		*c = in
		if c.Web.Password == "" {
			c.Web.Password = pw
		}
		if c.NDMC == "" {
			c.NDMC = old.NDMC
		}
		if c.RCI == "" {
			c.RCI = old.RCI
		}
		if c.NDMC != old.NDMC || c.RCI != old.RCI {
			return errors.New("ndmc и rci меняются только в файле конфигурации")
		}
		return nil
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	a.logf("info", "конфигурация обновлена через веб-интерфейс")
	a.applyConfig(n)
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) hPin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		Outlet string `json:"outlet"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
		writeErr(w, 400, err)
		return
	}
	_, err := a.store.Update(func(c *Config) error {
		g := c.group(name)
		if g == nil {
			return fmt.Errorf("нет группы %q", name)
		}
		g.Pinned = in.Outlet
		return nil
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if in.Outlet == "" {
		a.logf("info", "группа %s: закрепление снято, выбор автоматический", name)
	} else {
		a.logf("info", "группа %s: вручную закреплён выход %s", name, in.Outlet)
	}
	a.evaluate()
	writeJSON(w, map[string]any{"ok": true})
}
