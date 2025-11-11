package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
)

/*  MODELS  */

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

func GenerateState() string {
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

func NewAuthRequest(clientID string, redirectURI string, scope string) *AuthRequest {
	return &AuthRequest{
		ResponseType: "code",
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		Scope:        scope,
		State:        GenerateState(), // Generate a random state value
	}
}

func main() {
	/*  LOAD ENVIRONMENT  */

	err := godotenv.Load()
	if err != nil {
		panic("Unable to load .env file")
	}

	CLIENT_PORT := os.Getenv("CLIENT_PORT")
	if CLIENT_PORT == "" {
		panic("PORT is not set")
	}

	CLIENT_URI := os.Getenv("CLIENT_URI")
	if CLIENT_URI == "" {
		panic("CLIENT_URI is not set")
	}

	AUTH_URI := os.Getenv("AUTH_URI")
	if AUTH_URI == "" {
		panic("AUTH_URI is not set")
	}

	CLIENT_SECRET := os.Getenv("CLIENT_SECRET")
	if CLIENT_SECRET == "" {
		panic("CLIENT_SECRET is not set")
	}

	CLIENT_ID := os.Getenv("CLIENT_ID")
	if CLIENT_ID == "" {
		panic("CLIENT_ID is not set")
	}

	/*  FIBER WEB FRAMEWORK  */

	engine := html.New("./client/views", ".html")

	clientServer := fiber.New(fiber.Config{
		AppName: "Client",
		Views:   engine,
	})

	clientServer.Use(logger.New())
	clientServer.Use(recover.New())

	// Fiber Routes & Handlers
	clientServer.Get("/", func(c *fiber.Ctx) error {
		// Clear the Secure Cookie
		c.ClearCookie("request_state")
		c.ClearCookie("grant_code")

		// Create Auth grant request
		authRequest := NewAuthRequest(CLIENT_ID, CLIENT_URI+"/callback", "all")
		if err := c.QueryParser(authRequest); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request",
			})
		}

		// Store state value in Secure Cookie
		c.Cookie(&fiber.Cookie{
			Name:     "request_state",
			Value:    authRequest.State,
			Secure:   true,
			Expires:  time.Now().Add(5 * time.Minute),
			HTTPOnly: true,
		})

		return c.Render("login", fiber.Map{
			"AuthorizeURI": fmt.Sprintf("%s/auth?response_type=%s&client_id=%s&redirect_uri=%s&scope=%s&state=%s", AUTH_URI, authRequest.ResponseType, authRequest.ClientID, authRequest.RedirectURI, authRequest.Scope, authRequest.State),
		})
	})

	clientServer.Get("/callback", func(c *fiber.Ctx) error {
		// Get the code and state
		code := c.Query("code")
		state := c.Query("state")

		// Validate the state value from the Secure Cookie and Delete the Secure Cookie
		cookie := c.Cookies("request_state")
		if cookie != state {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid state",
			})
		}
		c.ClearCookie("request_state")

		// Generate Token Request
		tokenRequest := url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {code},
			"redirect_uri": {CLIENT_URI + "/callback"},

			/*  Public client data implementation includes ID and Secret in the body of the request
			Private client data implementation includes ID and Secret in the header of the request

			"client_id":    {CLIENT_ID},
			"client_secret":{CLIENT_SECRET},  */
		}

		// Create Post request for token
		agent := fiber.Post(AUTH_URI + "/token")

		agent.BodyString(tokenRequest.Encode())
		agent.ContentType("application/x-www-form-urlencoded")
		agent.BasicAuth(CLIENT_ID, CLIENT_SECRET)
		agent.Cookie("grant_code", code)

		c.ClearCookie("grant_code")

		defer agent.ConnectionClose()

		if err := agent.Parse(); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Bad Request",
			})
		}

		statusCode, body, errs := agent.Bytes()
		if len(errs) > 0 {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to request token",
			})
		}

		return c.Status(statusCode).Send(body)
	})

	clientServer.Listen(fmt.Sprintf(":%s", CLIENT_PORT))
}
