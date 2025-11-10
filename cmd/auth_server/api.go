package authserver

import (
	"time"

	"golang.org/x/mod/sumdb/storage"
)

type application struct {
	config  config
	storage storage.Storage
}

type config struct {
	addr string
	db   dbConfig
}

type dbConfig struct {
	dsn          string
	maxOpenConns int
	maxIdleConns int
	maxIdleTime  time.Duration // nanoseconds
}
