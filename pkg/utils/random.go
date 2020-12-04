// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"encoding/base32"
	"math/rand"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seed *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()),
)

func gen(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seed.Intn(len(charset))]
	}
	return string(b)
}

// GetRandomString returns X character long random string.
func GetRandomString(i int) string {
	if i < 1 {
		i = 40
	}
	return gen(i, charset)
}

// GetRandomStringFromRange generates random string of a random length. The
// random lenght is bounded by a and b.
func GetRandomStringFromRange(a, b int) string {
	var i int
	if a > b {
		i = rand.Intn(a-b) + b
	} else {
		i = rand.Intn(b-a) + a
	}
	return gen(i, charset)
}

// GetRandomEncodedStringFromRange return the number returned by
// GetRandomStringFromRange() and encoded with Base32
func GetRandomEncodedStringFromRange(a, b int) string {
	s := GetRandomStringFromRange(a, b)
	return base32.StdEncoding.EncodeToString([]byte(s))
}
