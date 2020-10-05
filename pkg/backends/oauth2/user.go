package oauth2

import (
	"encoding/json"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"time"
)

func (b *Backend) fetchClaims(tokenData map[string]interface{}) (*jwt.UserClaims, error) {
	var userURL string

	switch b.Provider {
	case "github":
		userURL = "https://api.github.com/user"
	default:
		return nil, fmt.Errorf("provider %s is unsupported for fetching claims", b.Provider)
	}

	for _, k := range []string{"access_token"} {
		if _, exists := tokenData[k]; !exists {
			return nil, fmt.Errorf("token response has no %s field", k)
		}
	}

	tokenString := tokenData["access_token"].(string)

	cli, err := newBrowser()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Add("Authorization", "token "+tokenString)

	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	b.logger.Debug(
		"User profile received",
		zap.Any("body", respBody),
	)

	data := make(map[string]interface{})
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, err
	}
	if _, exists := data["message"]; exists {
		return nil, fmt.Errorf("failed obtaining user profile with OAuth 2.0 access token, error: %s", data["message"].(string))
	}

	if _, exists := data["login"]; !exists {
		return nil, fmt.Errorf("failed obtaining user profile with OAuth 2.0 access token, login field not found")
	}

	// Create new claims
	claims := &jwt.UserClaims{
		//ID:        tokenID,
		Origin:    userURL,
		ExpiresAt: time.Now().Add(time.Duration(b.TokenProvider.TokenLifetime) * time.Second).Unix(),
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Add(10 * time.Minute * -1).Unix(),
	}

	if _, exists := data["login"]; exists {
		claims.Subject = "github.com/" + data["login"].(string)
	}

	if _, exists := data["name"]; !exists {
		claims.Name = data["name"].(string)
	}

	if len(claims.Roles) < 1 {
		claims.Roles = []string{"anonymous", "guest", "everyone"}
	}

	return claims, nil
}
