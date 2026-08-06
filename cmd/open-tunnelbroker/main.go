package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/open-tunnelbroker/open-tunnelbroker/internal/broker"
)

var version = "dev"

func main() {
	var dbPath, listen, adminUser, adminPassword string
	var dryRun, showVersion bool
	flag.StringVar(&dbPath, "db", "/var/lib/open-tunnelbroker/broker.db", "SQLite database path")
	flag.StringVar(&listen, "listen", "127.0.0.1:8080", "HTTP listen address")
	flag.StringVar(&adminUser, "admin-user", env("OTB_ADMIN_USER", "admin"), "bootstrap admin username")
	flag.StringVar(&adminPassword, "admin-password", os.Getenv("OTB_ADMIN_PASSWORD"), "bootstrap admin password (prefer OTB_ADMIN_PASSWORD)")
	flag.BoolVar(&dryRun, "dry-run", false, "do not change kernel networking")
	flag.BoolVar(&showVersion, "version", false, "print version")
	flag.Parse()
	if showVersion {
		fmt.Println(version)
		return
	}

	logger := log.New(os.Stdout, "open-tunnelbroker: ", log.LstdFlags|log.LUTC)
	app, err := broker.New(dbPath, dryRun, logger)
	if err != nil {
		logger.Fatal(err)
	}
	defer app.Close()
	if err := app.BootstrapAdmin(adminUser, adminPassword); err != nil {
		logger.Fatal(err)
	}
	if err := app.Reconcile(context.Background()); err != nil {
		logger.Printf("initial reconcile: %v", err)
	}
	reconcileCtx, cancelReconcile := context.WithCancel(context.Background())
	defer cancelReconcile()
	go app.RunReconciler(reconcileCtx, 30*time.Second)

	srv := &http.Server{Addr: listen, Handler: app.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		logger.Printf("version %s listening on %s", version, listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal(err)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
