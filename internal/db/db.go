package db

import(
	"time"
)

type Client struct {
	ClientID     string    `json:"client_id" gorm:"uniqueIndex"`
	ClientName   string    `json:"client_name" gorm:"primaryKey"`
	ClientSecret string    `json:"-"`
	Website      string    `json:"website"`
	RedirectURI  string    `json:"redirect_uri"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	DeletedAt    time.Time `json:"-" gorm:"deleted_at"`
}