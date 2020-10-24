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
	"fmt"
	"strings"
)

const allowedChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/_-.!~"

// ContainsInvalidChars returns error if the provided string contains
// characters outside of the allowed character set.
func ContainsInvalidChars(charset, s string) error {
	for i, c := range s {
		if !strings.Contains(charset, strings.ToLower(string(c))) &&
			!strings.Contains(charset, strings.ToUpper(string(c))) {
			return fmt.Errorf("string %s contains forbidden character %d, pos: %d", s, c, i)
		}
	}
	return nil
}

// ContainsValidCharset returns error if the provided string contains
// characters outside of the provided character set.
func ContainsValidCharset(charset, s string) error {
	for i, c := range s {
		if !strings.Contains(charset, string(c)) {
			return fmt.Errorf("string %s contains forbidden character %d, pos: %d", s, c, i)
		}
	}
	return nil
}
