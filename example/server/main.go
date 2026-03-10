package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/redis/go-redis/v9"

	"github.com/zitadel/oidc/v3/example/server/config"
	"github.com/zitadel/oidc/v3/example/server/exampleop"
	"github.com/zitadel/oidc/v3/example/server/storage"
)

func getUserStore(cfg *config.Config) (storage.UserStore, error) {
	if cfg.UsersFile == "" {
		return storage.NewUserStore(fmt.Sprintf("http://localhost:%s/", cfg.Port)), nil
	}
	return storage.StoreFromFile(cfg.UsersFile)
}

func main() {
	cfg := config.FromEnvVars(&config.Config{Port: "9998"})
	logger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelDebug,
		}),
	)

	issuer := fmt.Sprintf("http://localhost:%s/", cfg.Port)

	storage.RegisterClients(
		storage.NativeClient("native", cfg.RedirectURI...),
		storage.WebClient("web", "secret", cfg.RedirectURI...),
		storage.WebClient("api", "secret", cfg.RedirectURI...),
	)

	store, err := getUserStore(cfg)
	if err != nil {
		logger.Error("cannot create UserStore", "error", err)
		os.Exit(1)
	}

	var stor exampleop.Storage

	storageType := os.Getenv("STORAGE_TYPE")
	switch storageType {
	case "redis":
		redisAddr := os.Getenv("REDIS_ADDR")
		if redisAddr == "" {
			redisAddr = "localhost:6379"
		}
		redisPassword := os.Getenv("REDIS_PASSWORD")
		rdb := redis.NewClient(&redis.Options{
			Addr:     redisAddr,
			Password: redisPassword,
			DB:       10,
		})
		stor = storage.NewRedisStorage(rdb, store, "oidc:")
		logger.Info("using Redis storage", "addr", redisAddr)
	default:
		stor = storage.NewStorage(store)
		logger.Info("using in-memory storage")
	}

	router := exampleop.SetupServer(
		issuer,
		stor,
		logger,
		false,
	)

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}
	logger.Info("server listening, press ctrl+c to stop", "addr", issuer)
	if server.ListenAndServe() != http.ErrServerClosed {
		logger.Error("server terminated", "error", err)
		os.Exit(1)
	}
}
