// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cache

import (
	"fmt"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
)

const (
	memory    = "memory"
	memcached = "memcached"
)

var (
	validCacheTypes = map[string]bool{
		memory:    true,
		memcached: true,
	}
)

// Cache stores the state of the OAuth2 flow.
type Cache interface {
	Init() error
	Add(key string, data interface{}) error
	Get(key string, output interface{}) error
	Del(key string) error
	Exists(key string) (bool, error)
}

func Validate(name string) error {
	_, ok := validCacheTypes[name]
	if !ok {
		return errors.ErrCacheBackendNotFound.WithArgs(name)
	}
	return nil
}

func RequiresParameters(name string) bool {
	switch name {
	case memory:
		return false
	case memcached:
		return true
	default:
		panic(fmt.Sprintf("invalid cache type supplied %s", name))
	}
}

func NewFromName(name string) Cache {
	switch name {
	case memory:
		return NewMemoryCache()
	default:
		panic(fmt.Sprintf("invalid cache provided %s", name))
	}
}

func NewFromArgs(name string, args []string) Cache {
	switch name {
	case memory:
		return NewMemoryCache()
	case memcached:
		return NewMemcachedCache(args...)
	default:
		panic(fmt.Sprintf("invalid cache provided %s", name))
	}
}
