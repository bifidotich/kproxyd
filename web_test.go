package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testApp(t *testing.T) (*App, func()) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	initialCfg := `{"web":{"listen":":8088","user":"admin","password":"secretpassword"},"outlets":[],"groups":[]}`
	if err := os.WriteFile(cfgPath, []byte(initialCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	store, _, err := loadStore(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	app := newApp(store)
	return app, func() {
		os.RemoveAll(tmpDir)
	}
}

func TestWebAuth(t *testing.T) {
	app, cleanup := testApp(t)
	defer cleanup()
	handler := app.routes()

	// 1. GET / serves HTML, status 200, no WWW-Authenticate header
	{
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for GET /, got %d", rec.Code)
		}
		if authHdr := rec.Header().Get("WWW-Authenticate"); authHdr != "" {
			t.Fatalf("WWW-Authenticate header must NOT be present on GET /, got %q", authHdr)
		}
		if !strings.Contains(rec.Body.String(), "kproxyd") {
			t.Fatalf("expected HTML body to contain kproxyd")
		}
	}

	// 2. GET /api/state without auth returns 401 without WWW-Authenticate header
	{
		req := httptest.NewRequest("GET", "/api/state", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for GET /api/state without auth, got %d", rec.Code)
		}
		if authHdr := rec.Header().Get("WWW-Authenticate"); authHdr != "" {
			t.Fatalf("WWW-Authenticate header must NOT be present on 401 API responses, got %q", authHdr)
		}
	}

	// 3. POST /api/login with wrong credentials returns 401 without WWW-Authenticate header
	{
		body := bytes.NewBufferString(`{"user":"admin","password":"wrong"}`)
		req := httptest.NewRequest("POST", "/api/login", body)
		req.RemoteAddr = "127.0.0.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for bad login, got %d", rec.Code)
		}
		if authHdr := rec.Header().Get("WWW-Authenticate"); authHdr != "" {
			t.Fatalf("WWW-Authenticate header must NOT be present on login error, got %q", authHdr)
		}
	}

	// 4. POST /api/login with correct credentials returns 200 and sets kproxyd_session cookie
	var sessionCookie *http.Cookie
	{
		body := bytes.NewBufferString(`{"user":"admin","password":"secretpassword"}`)
		req := httptest.NewRequest("POST", "/api/login", body)
		req.RemoteAddr = "127.0.0.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for valid login, got %d", rec.Code)
		}
		cookies := rec.Result().Cookies()
		for _, c := range cookies {
			if c.Name == sessionCookieName {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil || sessionCookie.Value == "" {
			t.Fatalf("expected kproxyd_session cookie to be set")
		}
		if !sessionCookie.HttpOnly {
			t.Fatalf("cookie must be HttpOnly")
		}
	}

	// 5. GET /api/state with kproxyd_session cookie returns 200
	{
		req := httptest.NewRequest("GET", "/api/state", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.AddCookie(sessionCookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for authenticated GET /api/state, got %d: %s", rec.Code, rec.Body.String())
		}
		var state map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
			t.Fatalf("failed to decode state JSON: %v", err)
		}
	}

	// 6. Basic Auth header also works for /api/state
	{
		req := httptest.NewRequest("GET", "/api/state", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.SetBasicAuth("admin", "secretpassword")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for Basic Auth GET /api/state, got %d", rec.Code)
		}
	}

	// 7. POST /api/logout clears session cookie
	{
		req := httptest.NewRequest("POST", "/api/logout", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Kproxyd", "1")
		req.AddCookie(sessionCookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for POST /api/logout, got %d", rec.Code)
		}
		cookies := rec.Result().Cookies()
		cleared := false
		for _, c := range cookies {
			if c.Name == sessionCookieName && (c.MaxAge < 0 || c.Value == "") {
				cleared = true
				break
			}
		}
		if !cleared {
			t.Fatalf("expected kproxyd_session cookie to be cleared on logout")
		}
	}

	// 8. CSRF check: mutating requests without X-Kproxyd header must be rejected
	{
		body := bytes.NewBufferString(`{"outlet":"test"}`)
		req := httptest.NewRequest("POST", "/api/groups/test/pin", body)
		req.RemoteAddr = "127.0.0.1:12345"
		req.AddCookie(sessionCookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden without X-Kproxyd header, got %d", rec.Code)
		}
	}
}
