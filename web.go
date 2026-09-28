package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed ui/index.html
var uiFS embed.FS

const (
	sessionCookieName = "kproxyd_session"
	sessionDuration   = 30 * 24 * time.Hour
)

func sessionKey(c *Config) []byte {
	h := sha256.Sum256([]byte(c.Web.Password + ":" + c.Web.User))
	return h[:]
}

func createSessionToken(c *Config) string {
	exp := time.Now().Add(sessionDuration).Unix()
	payload := fmt.Sprintf("%d:%s", exp, c.Web.User)
	mac := hmac.New(sha256.New, sessionKey(c))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%d.%s", exp, sig)
}

func validateSessionCookie(val string, c *Config) bool {
	parts := strings.SplitN(val, ".", 2)
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	payload := fmt.Sprintf("%d:%s", exp, c.Web.User)
	mac := hmac.New(sha256.New, sessionKey(c))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedSig)) == 1
}

func (a *App) checkAuth(r *http.Request, c *Config) bool {
	if u, p, ok := r.BasicAuth(); ok {
		if subtle.ConstantTimeCompare([]byte(u), []byte(c.Web.User)) == 1 &&
			subtle.ConstantTimeCompare([]byte(p), []byte(c.Web.Password)) == 1 {
			return true
		}
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil && cookie.Value != "" {
		if validateSessionCookie(cookie.Value, c) {
			return true
		}
	}
	return false
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := uiFS.ReadFile("ui/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /index.html", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("POST /api/login", a.hLogin)
	mux.HandleFunc("POST /api/logout", a.hLogout)
	mux.HandleFunc("GET /api/state", a.hState)
	mux.HandleFunc("PUT /api/config", a.hPutConfig)
	mux.HandleFunc("POST /api/groups/{name}/pin", a.hPin)
	mux.HandleFunc("POST /api/groups/{name}/watch", func(w http.ResponseWriter, r *http.Request) {
		a.watchSoon(r.PathValue("name"))
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /api/sites", a.hSites)
	mux.HandleFunc("POST /api/sites/reset", a.hSiteReset)
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
		// Главная страница и авторизация доступны без активной сессии
		if r.URL.Path == "/" || r.URL.Path == "/index.html" || r.URL.Path == "/api/login" {
			next.ServeHTTP(w, r)
			return
		}
		if !a.checkAuth(r, c) {
			// Не отправляем WWW-Authenticate: Basic, чтобы браузер не показывал системное модальное окно
			writeErr(w, http.StatusUnauthorized, errors.New("unauthorized"))
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

func (a *App) hLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	c := a.store.Get()
	if subtle.ConstantTimeCompare([]byte(in.User), []byte(c.Web.User)) != 1 ||
		subtle.ConstantTimeCompare([]byte(in.Password), []byte(c.Web.Password)) != 1 {
		writeErr(w, http.StatusUnauthorized, errf("неверный логин или пароль"))
		return
	}
	token := createSessionToken(c)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) hLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	writeJSON(w, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	t := errText(err)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": t.Ru, "error_en": t.En})
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
	healthy := a.healthyOutlets()
	a.mu.RUnlock()

	for i := range grs {
		if g := c.group(grs[i].Name); g != nil && (g.Sniff || len(g.Watch) > 0) {
			grs[i].Sites = a.sites.summary(siteView{g: g, active: grs[i].Active, healthy: healthy})
		}
	}

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
		"k_error":    kerr.Ru,
		"k_error_en": kerr.En,
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
			return errf("ndmc и rci меняются только в файле конфигурации")
		}
		return nil
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	a.logf("info", "конфигурация обновлена через веб-интерфейс")
	a.applyConfig(n)
	if (n.Web.Password != old.Web.Password && old.Web.Password != "") || n.Web.User != old.Web.User {
		token := createSessionToken(n)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(sessionDuration.Seconds()),
		})
	}
	writeJSON(w, map[string]any{"ok": true})
}

// healthyOutlets — рабочие подключения. Вызывать под a.mu.
func (a *App) healthyOutlets() map[string]bool {
	m := map[string]bool{}
	for n, st := range a.outlets {
		m[n] = st.Enabled && st.Healthy && st.Dev != ""
	}
	return m
}

// hSites — мониторинг ресурсов группы: ?group=имя&traffic=1&limit=100
func (a *App) hSites(w http.ResponseWriter, r *http.Request) {
	c := a.store.Get()
	g := c.group(r.URL.Query().Get("group"))
	if g == nil {
		writeErr(w, 404, errf("нет такого узла"))
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > siteMax {
		limit = 100
	}
	a.mu.RLock()
	healthy := a.healthyOutlets()
	var active string
	if gs := a.groups[g.Name]; gs != nil {
		active = gs.Active
	}
	a.mu.RUnlock()
	rows, total, st := a.sites.rows(siteView{g: g, active: active, healthy: healthy}, r.URL.Query().Get("traffic") != "0", limit)
	if rows == nil {
		rows = []SiteRow{}
	}
	writeJSON(w, map[string]any{"group": g.Name, "members": g.Members, "active": active,
		"rows": rows, "total": total, "stats": st})
}

func (a *App) hSiteReset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Group string `json:"group"`
		Site  string `json:"site"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
		writeErr(w, 400, err)
		return
	}
	a.sites.reset(in.Group, in.Site)
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
			return errf("нет узла %q", name)
		}
		g.Pinned = in.Outlet
		return nil
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if in.Outlet == "" {
		a.logf("info", "узел %s: закрепление снято, выбор автоматический", name)
	} else {
		a.logf("info", "узел %s: вручную закреплено подключение %s", name, in.Outlet)
	}
	a.evaluate()
	writeJSON(w, map[string]any{"ok": true})
}
