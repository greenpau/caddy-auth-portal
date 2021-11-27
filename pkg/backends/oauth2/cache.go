package oauth2

import (
	"fmt"
)

func getStateCacheKey(state string) string {
	return fmt.Sprintf("caddy-auth-portal-state-%s", state)
}

func getCodeCacheKey(state string) string {
	return fmt.Sprintf("caddy-auth-portal-code-%s", state)
}
