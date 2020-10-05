package cache

import (
	"github.com/greenpau/caddy-auth-jwt"
	//"log"
	"sync"
	"time"
)

// SessionCache contains cached tokens
type SessionCache struct {
	mu      sync.RWMutex
	Entries map[string]interface{}
}

// NewSessionCache returns SessionCache instance.
func NewSessionCache() *SessionCache {
	c := &SessionCache{
		Entries: map[string]interface{}{},
	}
	go manageSessionCache(c)
	return c
}

func manageSessionCache(cache *SessionCache) {
	intervals := time.NewTicker(time.Minute * time.Duration(5))
	for range intervals.C {
		//log.Printf("managing cache")
		if cache == nil {
			//log.Printf("cache is nil")
			return
		}
		cache.mu.RLock()
		if cache.Entries == nil {
			//log.Printf("cache entries is nil")
			cache.mu.RUnlock()
			continue
		}
		cache.mu.RUnlock()
		cache.mu.Lock()
		//log.Printf("cache entries count: %d", len(cache.Entries))
		for entryID, data := range cache.Entries {
			//log.Printf("entering cache entry: %s", entryID)
			switch data.(type) {
			case map[string]interface{}:
				//log.Printf("cached entry is map[string]interface")
				dataset := data.(map[string]interface{})
				//log.Printf("cached entry data: %v", dataset)
				if v, exists := dataset["claims"]; exists {
					claims := v.(*jwt.UserClaims)
					//log.Printf("entering cache claims: %v", claims)
					if err := claims.Valid(); err != nil {
						delete(cache.Entries, entryID)
					}
				}
			default:
				continue
			}
		}
		cache.mu.Unlock()
	}
	return
}

// Add adds data to the cache.
func (c *SessionCache) Add(entryID string, data interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Entries[entryID] = data
	return nil
}

// Delete removes cached data entry.
func (c *SessionCache) Delete(entryID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.Entries, entryID)
	return nil
}

// Get returns cached data entry.
func (c *SessionCache) Get(entryID string) interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, exists := c.Entries[entryID]
	if !exists {
		return nil
	}
	return data
}
