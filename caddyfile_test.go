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

package portal

import (
	"encoding/json"
	"github.com/caddyserver/caddy/v2/caddytest"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLocalCaddyfile(t *testing.T) {
	scheme := "https"
	host := "127.0.0.1"
	securePort := "8443"
	authPath := "auth"
	hostPort := host + ":" + securePort
	baseURL := scheme + "://" + hostPort
	accessTokenName := "access_token"
	localhost, _ := url.Parse(baseURL)

	tester := caddytest.NewTester(t)
	configFile := "assets/conf/local/Caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")
	req, _ := http.NewRequest("POST", baseURL+"/"+authPath, strings.NewReader("username=webadmin&password=password123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := tester.AssertResponseCode(req, 200)
	var accessToken string
	for _, cookie := range tester.Client.Jar.Cookies(localhost) {
		t.Logf("Found a cookie named: %s", cookie.Name)
		if cookie.Name == accessTokenName {
			accessToken = cookie.Value
			t.Logf("Found %s cookie: %s", accessTokenName, accessToken)
			break
		}
	}

	if accessToken == "" {
		t.Fatalf("access token not found in response")
	}

	req, _ = http.NewRequest("GET", baseURL+"/"+authPath+"/whoami", nil)
	req.Header.Set("Accept", "application/json")
	resp = tester.AssertResponseCode(req, 200)
	responseBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("failed reading response body: %s", err)
	}
	whoami := make(map[string]interface{})
	if err := json.Unmarshal(responseBody, &whoami); err != nil {
		t.Fatalf("failed parsing response body %s\nerror: %s", responseBody, err)
	}
	expectedSub := "webadmin"
	if whoami["sub"].(string) != expectedSub {
		t.Fatalf(
			"response subject mismatch: %s (expected) vs. %s (received), response %s",
			expectedSub, whoami["sub"], whoami,
		)
	}
	t.Logf("Valid Response: %v", whoami)
	time.Sleep(1 * time.Second)
}

func TestLdapCaddyfile(t *testing.T) {
	scheme := "https"
	host := "127.0.0.1"
	securePort := "8443"
	authPath := "auth"
	hostPort := host + ":" + securePort
	baseURL := scheme + "://" + hostPort
	tester := caddytest.NewTester(t)
	configFile := "assets/conf/ldap/Caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")
	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")
	req, _ := http.NewRequest(
		"POST",
		baseURL+"/"+authPath,
		strings.NewReader("username=webadmin&password=password123&realm=local"),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := tester.AssertResponseCode(req, 200)
	t.Logf("%v", resp)
	time.Sleep(1 * time.Second)
}

func TestSamlCaddyfile(t *testing.T) {
	scheme := "https"
	host := "127.0.0.1"
	securePort := "8443"
	authPath := "auth"
	hostPort := host + ":" + securePort
	baseURL := scheme + "://" + hostPort
	tester := caddytest.NewTester(t)
	configFile := "assets/conf/saml/azure/Caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")
	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")
	req, _ := http.NewRequest(
		"POST",
		baseURL+"/"+authPath,
		strings.NewReader("username=webadmin&password=password123&realm=local"),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := tester.AssertResponseCode(req, 200)
	t.Logf("%v", resp)
	time.Sleep(1 * time.Second)
}

func TestShortLocalCaddyfile(t *testing.T) {
	scheme := "https"
	host := "127.0.0.1"
	securePort := "8443"
	authPath := "auth"
	hostPort := host + ":" + securePort
	baseURL := scheme + "://" + hostPort
	tester := caddytest.NewTester(t)
	configFile := "assets/conf/local/Caddyfile.short"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")
	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")
	req, _ := http.NewRequest(
		"POST",
		baseURL+"/"+authPath,
		strings.NewReader("username=webadmin&password=password123&realm=local"),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := tester.AssertResponseCode(req, 200)
	t.Logf("%v", resp)
	time.Sleep(1 * time.Second)
}
