package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
	"github.com/lucsky/cuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

/*  MODELS  */

// Postgres database model
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

type AuthRequest struct {
	ResponseType string `json:"response_type" query:"response_type"`
	ClientID     string `json:"client_id" query:"client_id"`
	RedirectURI  string `json:"redirect_uri" query:"redirect_uri"`
	Scope        string `json:"scope" query:"scope"`
	State        string `json:"state" query:"state"`
}

type AuthGrant struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

type TokenRequestBody struct {
	GrantType   string `json:"grant_type" form:"grant_type"`
	Code        string `json:"code" form:"code"`
	RedirectURI string `json:"redirect_uri" form:"redirect_uri"`
}

type TokenRequestHeader struct {
	Host          string `json:"Host" reqHeader:"Host"`
	ContentType   string `json:"Content-Type" reqHeader:"Content-Type"`
	Authorization string `json:"Authorization" reqHeader:"Authorization"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	// RefreshToken string `json:"refresh_token"` should add eventually
}

func NewAuthGrant(code string, state string) *AuthGrant {
	return &AuthGrant{
		Code:  code,
		State: state,
	}
}

func DecodeBasicAuthHeader(header string) (string, string, error) {
	// Validate the header format
	if !strings.HasPrefix(header, "Basic ") {
		return "", "", fmt.Errorf("invalid Authorization header format")
	}

	// Separate base64 encoded credentials
	auth := strings.SplitN(header, " ", 2)
	if len(auth) != 2 {
		return "", "", fmt.Errorf("invalid Authorization header format")
	}

	// Decode base64 credentials
	decoded, err := base64.StdEncoding.DecodeString(auth[1])
	if err != nil {
		return "", "", fmt.Errorf("failed to decode base64: %v", err)
	}

	// Split credentials into ClientID and ClientSecret
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return "", "", fmt.Errorf("invalid credentials format")
	}

	return credentials[0], credentials[1], nil
}

func GenerateToken() string {
	// Generate random bytes
	randomBytes := make([]byte, 1024)
	if _, err := rand.Read(randomBytes); err != nil {
		panic("Unable to generate random state value")
	}

	// Calculate SHA-256 hash
	hash := sha256.Sum256(randomBytes)

	// Convert hash to hex string
	hexString := hex.EncodeToString(hash[:])

	return hexString
}

func main() {
	/*  LOAD ENVIRONMENT  */

	err := godotenv.Load()
	if err != nil {
		panic("Unable to load .env file")
	}

	AUTH_PORT := os.Getenv("AUTH_PORT")
	if AUTH_PORT == "" {
		panic("PORT is not set")
	}

	CLIENT_ID := os.Getenv("CLIENT_ID")
	if CLIENT_ID == "" {
		panic("CLIENT_ID is not set")
	}

	CLIENT_NAME := os.Getenv("CLIENT_NAME")
	if CLIENT_NAME == "" {
		panic("CLIENT_NAME is not set")
	}

	CLIENT_SECRET := os.Getenv("CLIENT_SECRET")
	if CLIENT_SECRET == "" {
		panic("CLIENT_SECRET is not set")
	}

	CLIENT_URI := os.Getenv("CLIENT_URI")
	if CLIENT_URI == "" {
		panic("CLIENT_URI is not set")
	}

	AUTH_URI := os.Getenv("AUTH_URI")
	if AUTH_URI == "" {
		panic("AUTH_URI is not set")
	}

	/*  DATABASE SETUP  */

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		panic("DATABASE_URL is not set")
	}

	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		panic("Failed to connect")
	}

	// Clear database for testing purposes
	db.Exec("DELETE FROM clients")

	db.AutoMigrate(&Client{})

	// Create client
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "client_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"client_name", "website", "redirect_uri", "client_secret"}),
	}).Create(&Client{
		ClientID:     CLIENT_ID,
		ClientName:   CLIENT_NAME,
		Website:      CLIENT_URI,               // Website you want access to
		RedirectURI:  CLIENT_URI + "/callback", // Should be HTTPS in production
		ClientSecret: CLIENT_SECRET,
	})

	/*  FIBER WEB FRAMEWORK  */

	engine := html.New("./authorization/views", ".html")

	authServer := fiber.New(fiber.Config{
		AppName: "Authorization Service",
		Views:   engine,
	})

	authServer.Use(logger.New())
	authServer.Use(recover.New())

	// Fiber Routes & Handlers
	authServer.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("OAuth 2.0 Authorization Server")
	})

	// Authorization Code Flow Implementation
	authServer.Get("/auth", func(c *fiber.Ctx) error {
		// Auth Request Validation
		authRequest := new(AuthRequest)
		if err := c.QueryParser(authRequest); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request",
			})
		}

		if authRequest.ResponseType != "code" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid response type"})
		}

		if authRequest.ClientID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid client ID",
			})
		}

		// Should use https for production
		if !strings.Contains(authRequest.RedirectURI, "http") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid redirect URI",
			})
		}

		if authRequest.Scope == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid scope",
			})
		}

		if authRequest.State == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid state",
			})
		}

		// Should add a login system here for users of client website

		// Validate client web server
		client := new(Client)
		if err := db.Where("client_id = ?", authRequest.ClientID).First(&client).Error; err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Client not found",
			})
		}

		if client.RedirectURI != authRequest.RedirectURI {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid redirect URI",
			})
		}

		if client.ClientID != authRequest.ClientID {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid client ID",
			})
		}

		// Generate authorization grant
		code, err := cuid.NewCrypto(rand.Reader)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to generate auth code",
			})
		}

		authGrant := NewAuthGrant(code, authRequest.State)

		c.Cookie(&fiber.Cookie{
			Name:     "grant_code",
			Value:    authGrant.Code,
			Secure:   true,
			Expires:  time.Now().Add(5 * time.Minute),
			HTTPOnly: true,
		})

		return c.Render("auth", fiber.Map{
			"ClientName":  client.ClientName,
			"CallbackURI": fmt.Sprintf("%s?code=%s&state=%s", client.RedirectURI, authGrant.Code, authGrant.State),
			"DenyURI":     client.Website,
		})
	})

	authServer.Post("/token", func(c *fiber.Ctx) error {
		// Parse request
		header := new(TokenRequestHeader)
		if err := c.ReqHeaderParser(header); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Header parsing error",
			})
		}

		body := new(TokenRequestBody)
		if err := c.BodyParser(body); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Body parsing error",
			})
		}

		// Decode Basic Auth Header
		clientID, clientSecret, err := DecodeBasicAuthHeader(header.Authorization)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid client credentials",
			})
		}

		// Validate posted data, grant code, and delete secure cookie
		if body.GrantType != "authorization_code" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid grant type",
			})
		}

		if body.RedirectURI != CLIENT_URI+"/callback" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid redirect URI",
			})
		}

		cookie := c.Cookies("grant_code")
		if cookie != body.Code {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid grant code",
			})
		}
		c.ClearCookie("grant_code")

		// Validate Client ID and Secret
		if clientID != CLIENT_ID && clientSecret != CLIENT_SECRET {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid client credentials",
			})
		}

		// Generate access token and send response
		// Should store access token in cache for production
		return c.Status(fiber.StatusOK).JSON(TokenResponse{
			AccessToken: GenerateToken(),
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	})

	authServer.Listen(fmt.Sprintf(":%s", AUTH_PORT))
}
