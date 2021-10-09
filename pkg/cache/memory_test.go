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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemoryFlow(t *testing.T) {
	cache := NewMemoryCache()
	exists, err := cache.Exists("foo")
	assert.False(t, exists)
	assert.Nil(t, err, err)

	err = cache.Add("foo", "bar")
	assert.Nil(t, err, err)

	var rv string 
	err = cache.Get("foo", &rv)
	assert.Nil(t, err, err)
	assert.Equal(t, rv, "bar")

	err = cache.Del("foo")
	assert.Nil(t, err, err)

	err = cache.Del("foo")
	assert.Nil(t, err, err)
}
