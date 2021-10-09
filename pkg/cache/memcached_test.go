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
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	memcachedServer "github.com/mattrobenolt/go-memcached"
	"github.com/stretchr/testify/assert"
)

type TestCache map[string]*memcachedServer.Item

func (c TestCache) Get(key string) memcachedServer.MemcachedResponse {
	key = strings.TrimSpace(key) // the server library won't parse the command correctly
	if item, ok := c[key]; ok {
		if item.IsExpired() {
			delete(c, key)
		} else {
			return &memcachedServer.ItemResponse{item}
		}
	}
	return nil
}

func (c TestCache) Set(item *memcachedServer.Item) memcachedServer.MemcachedResponse {
	c[strings.TrimSpace(item.Key)] = item
	return nil
}

func (c TestCache) Delete(key string) memcachedServer.MemcachedResponse {
	delete(c, strings.TrimSpace(key))
	return nil
}

func newMemcachedServer() (*memcachedServer.Server, string) {
	rand.Seed(time.Now().UnixNano())
	port := rand.Int()%30000 + 1000
	address := fmt.Sprintf("127.0.0.1:%d", port)
	server := memcachedServer.NewServer(address, &TestCache{})
	go func() {
		if err := server.ListenAndServe(); err != nil {
			panic(err)
		}
	}()

	for {
		conn, err := net.Dial("tcp", address)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(time.Millisecond * 100)
	}
	return server, address
}

func TestMemcachedFlow(t *testing.T) {
	_, address := newMemcachedServer()
	stateManager := NewMemcachedCache(address)
	exists, err := stateManager.Exists("foo")
	assert.False(t, exists)
	assert.Nil(t, err, err)

	err = stateManager.Add("foo", "bar")
	assert.Nil(t, err, err)

	err = stateManager.Del("foo")
	assert.Nil(t, err, err)

	err = stateManager.Del("foo")
	assert.Nil(t, err, err)
}
