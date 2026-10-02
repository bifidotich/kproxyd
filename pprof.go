package main

import (
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"time"
)

// startPprof включает профилировщик Go, если задан KPROXYD_PPROF=адрес:порт (для диагностики нагрузки).
// Только loopback: снимок памяти содержит конфигурацию с паролями.
func startPprof() {
	addr := os.Getenv("KPROXYD_PPROF")
	if addr == "" {
		return
	}
	host, _, err := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		log.Printf("KPROXYD_PPROF=%q не принят: нужен адрес loopback, например 127.0.0.1:6060", addr)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("профилировщик: http://%s/debug/pprof/", addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("профилировщик: %v", err)
		}
	}()
}
