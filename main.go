package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	version   = "0.1.0"
	startedAt = time.Now()
)

func main() {
	cfgPath := flag.String("config", "/opt/etc/kproxyd/config.json", "путь к файлу конфигурации")
	logPath := flag.String("log", "", "писать журнал в этот файл с ротацией по 512 КБ (по умолчанию — в stderr)")
	flag.Parse()
	log.SetFlags(log.LstdFlags)
	if *logPath != "" {
		lf, err := openRotLog(*logPath, 512<<10)
		if err != nil {
			log.Fatalf("журнал: %v", err)
		}
		log.SetOutput(lf)
	}

	store, created, err := loadStore(*cfgPath)
	if err != nil {
		log.Fatalf("конфигурация: %v", err)
	}
	c := store.Get()
	if created {
		log.Printf("создан %s; вход в веб-интерфейс: %s / %s", *cfgPath, c.Web.User, c.Web.Password)
	}

	app := newApp(store)
	app.logf("info", "kproxyd %s запущен", version)

	ctx, cancel := context.WithCancel(context.Background())
	go app.probeLoop(ctx)
	go app.inspectLoop(ctx)

	srv := &http.Server{
		Addr:              c.Web.Listen,
		Handler:           app.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("веб-интерфейс на %s: %v", c.Web.Listen, err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	cancel()
	sctx, scancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer scancel()
	_ = srv.Shutdown(sctx)
	log.Printf("остановлен")
}
