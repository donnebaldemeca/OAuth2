package authtoken

import(
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

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
