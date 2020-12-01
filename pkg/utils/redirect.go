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
	"net/http"
	//	"strings"
)

// GetCurrentURL returns current URL
func GetCurrentURL(r *http.Request) string {
	return GetCurrentBaseURL(r) + r.URL.Path
}

// GetCurrentBaseURL returns current base URL
func GetCurrentBaseURL(r *http.Request) string {
	redirHost := r.Header.Get("X-Forwarded-Host")
	if redirHost == "" {
		redirHost = r.Host
	}
	redirProto := r.Header.Get("X-Forwarded-Proto")
	if redirProto == "" {
		if r.TLS == nil {
			redirProto = "http"
		} else {
			redirProto = "https"
		}
	}
	redirPort := r.Header.Get("X-Forwarded-Port")
	redirectBaseURL := redirProto + "://" + redirHost

	if redirPort != "" {
		switch redirPort {
		case "443":
			if redirProto != "https" {
				redirectBaseURL += ":" + redirPort
			}
		case "80":
			if redirProto != "http" {
				redirectBaseURL += ":" + redirPort
			}
		default:
			redirectBaseURL += ":" + redirPort
		}
	}

	return redirectBaseURL
}
