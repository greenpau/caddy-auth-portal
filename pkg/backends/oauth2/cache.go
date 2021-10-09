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

// ValidateNonce validate a nonce for the give state.
func (b *Backend) validateNonce(state, nonce string) error {
	stateKey := getStateCacheKey(state)
	stateExists, err := b.cache.Exists(stateKey)
	if err != nil {
		return fmt.Errorf("failed to check if state exists %v", err)
	}
	if !stateExists {
		return fmt.Errorf("no once found for %s", stateKey)
	}

	var storedState string

	err = b.cache.Get(stateKey, &storedState)
	if err != nil {
		return fmt.Errorf("failed to fetch state %s %w", state, err)
	}
	if storedState != nonce {
		return fmt.Errorf("nonce mismatch %s (expected) vs. %s (received)", storedState, nonce)
	}
	return nil
}
