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

package portal

import (
	"bytes"
	"encoding/json"
	"github.com/caddyserver/caddy/v2/caddytest"
	_ "github.com/greenpau/caddy-authorize"
	_ "github.com/greenpau/caddy-trace"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func initCaddyTester(t *testing.T, rules []string) (*caddytest.Tester, map[string]string, error) {
	scheme := "https"
	host := "127.0.0.1"
	securePort := "8443"
	authPath := "auth"
	hostPort := host + ":" + securePort
	baseURL := scheme + "://" + hostPort
	tester := caddytest.NewTester(t)
	tester.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Do not follow redirects.
		return http.ErrUseLastResponse
	}
	configFile := "assets/conf/local/Caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, nil, err
	}

	lines := []string{}
	for _, line := range strings.Split(string(configContent), "\n") {
		for _, rule := range rules {
			if strings.HasPrefix(rule, "uncomment:") {
				uncommentLine := strings.TrimPrefix(rule, "uncomment:")
				if strings.Contains(line, uncommentLine) {
					line = strings.Replace(line, "#", "", 1)
				}
			}
		}
		// t.Logf("line %d: %s", i, line)
		lines = append(lines, line)
	}

	tester.InitServer(strings.Join(lines, "\n"), "caddyfile")
	params := make(map[string]string)
	params["version_path"] = baseURL + "/version"
	params["auth_path"] = baseURL + "/" + authPath + "/login"
	return tester, params, nil
}

func initAuthRequest(authPath string) *http.Request {
	req, _ := http.NewRequest(
		"POST",
		authPath,
		strings.NewReader("username=webadmin&password=password123&realm=local"),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func initJSONAuthRequest(authPath string) *http.Request {
	req, _ := http.NewRequest(
		"POST",
		authPath,
		encodeUserCreds("webadmin", "password123", "local"),
	)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	return req
}

func encodeUserCreds(username, password, realm string) *bytes.Reader {
	m := make(map[string]string)
	m["username"] = username
	m["password"] = password
	m["realm"] = realm
	b, _ := json.Marshal(m)
	return bytes.NewReader(b)
}

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
	tester.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Do not follow redirects.
		return http.ErrUseLastResponse
	}

	configFile := "assets/conf/local/Caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")
	req, _ := http.NewRequest("POST", baseURL+"/"+authPath+"/login", encodeUserCreds("webadmin", "password123", "local"))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	tester.AssertResponseCode(req, 200)

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
	resp := tester.AssertResponseCode(req, 200)
	t.Logf("code: %v", resp.StatusCode)
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
	tester.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Do not follow redirects.
		return http.ErrUseLastResponse
	}
	configFile := "assets/conf/ldap/Caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")
	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")
	req, _ := http.NewRequest("POST", baseURL+"/"+authPath+"/login", encodeUserCreds("webadmin", "password123", "local"))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
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
	tester.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Do not follow redirects.
		return http.ErrUseLastResponse
	}
	configFile := "assets/conf/saml/azure/Caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")
	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")
	req, _ := http.NewRequest("POST", baseURL+"/"+authPath+"/login", encodeUserCreds("webadmin", "password123", "local"))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
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
	tester.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Do not follow redirects.
		return http.ErrUseLastResponse
	}
	configFile := "assets/conf/local/Caddyfile.short"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")
	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")
	req, _ := http.NewRequest("POST", baseURL+"/"+authPath+"/login", encodeUserCreds("webadmin", "password123", "local"))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp := tester.AssertResponseCode(req, 200)
	t.Logf("%v", resp)
	time.Sleep(1 * time.Second)
}

func TestCookieLifetime(t *testing.T) {
	rules := []string{
		"uncomment:crypto default token lifetime 900",
	}
	tester, config, err := initCaddyTester(t, rules)
	if err != nil {
		t.Fatalf("failed to init caddy tester instance: %s", err)
	}
	tester.AssertGetResponse(config["version_path"], 200, "1.0.0")
	authReq := initJSONAuthRequest(config["auth_path"])
	resp := tester.AssertResponseCode(authReq, 200)
	t.Logf("%v", resp)
	// TODO(greenpau): validate cookie lifetime
	/*
		cookieFound := false
		for _, c := range tester.Client.Jar.Cookies(authReq.URL) {
			t.Logf("received cookie: %s", c.Raw)
			if c.Name != "access_token" {
				continue
			}
			if c.MaxAge != 900 {
				t.Fatalf("cookie max age is not 900: %s", c.String())
			}
			cookieFound = true
		}
		if !cookieFound {
			t.Fatal("desired cookie not found")
		}
	*/
	time.Sleep(1 * time.Second)
}
