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

package handlers

import (
	"fmt"
	"net/http"
	"strings"
)

func validateKeyInputForm(r *http.Request) (map[string]string, error) {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("Unsupported content type")
	}
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("Failed parsing submitted form")
	}
	for _, k := range []string{"key1"} {
		if r.PostFormValue(k) == "" {
			return nil, fmt.Errorf("Required form field not found")
		}
	}
	if r.PostFormValue("key1") == "" {
		return nil, fmt.Errorf("Input is empty")
	}
	resp := make(map[string]string)
	resp["key"] = r.PostFormValue("key1")
	comment := r.PostFormValue("comment1")
	comment = strings.TrimSpace(comment)
	if comment != "" {
		resp["comment"] = comment
	}
	return resp, nil
}
