package authgrant

import(
	"fmt"
	"strings"
	"encoding/base64"
)

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