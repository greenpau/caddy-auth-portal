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

package authn

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/greenpau/caddy-authorize/pkg/acl"
	"github.com/greenpau/caddy-auth-portal/internal/tests"
	"github.com/greenpau/caddy-auth-portal/internal/utils"
	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/local"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
	"github.com/greenpau/go-identity/pkg/requests"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"net/http/httptest"
	"testing"
)

type testAuthRequest struct {
	endpoint    string
	username    string
	password    string
	realm       string
	contentType string
}

type testAppRequest struct {
	id          string
	method      string
	path        string
	headers     map[string]string
	query       map[string]string
	contentType string
}

func TestServeHTTP(t *testing.T) {
	db, err := tests.CreateTestDatabase("TestServeHTTP")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := db.GetPath()
	t.Logf("%v", dbPath)

	portal := &Authenticator{
		PrimaryInstance: true,
		Context:         "testservehttp",
		AccessListConfigs: []*acl.RuleConfiguration{
			{
				Conditions: []string{
					"match roles authp/admin",
				},
				Action: `allow`,
			},
		},
		BackendConfigs: []backends.Config{
			backends.Config{
				Local: &local.Config{
					Name:   "local_backend",
					Method: "local",
					Realm:  "localize",
					Path:   dbPath,
				},
			},
		},
	}
	portal.SetLogger(utils.NewLogger())
	if err := portal.Provision(); err != nil {
		t.Fatal(err)
	}
	if err := portal.Validate(); err != nil {
		t.Fatal(err)
	}

	var testcases = []struct {
		name     string
		disabled bool
		auth     *testAuthRequest
		requests []*testAppRequest
		// Expected results.
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "test unauthenticated json request to portal page",
			// disabled:    true,
			requests: []*testAppRequest{
				{
					method:      "GET",
					path:        "/auth/",
					contentType: "application/json",
					headers: map[string]string{
						"Accept": "application/json",
					},
				},
			},
			want: map[string]interface{}{
				"response": requests.Response{
					RedirectTokenName: "AUTHP_REDIRECT_URL",
				},
				"status_code":  http.StatusUnauthorized,
				"content_type": "application/json",
				"message":      "Access denied",
			},
		},
		{
			name: "test authenticate json request and get whoami page",
			//disabled: true,
			auth: &testAuthRequest{
				endpoint:    "/auth/login",
				username:    tests.TestUser1,
				password:    tests.TestPwd1,
				realm:       "localize",
				contentType: "application/json",
			},
			requests: []*testAppRequest{
				{
					method:      "GET",
					path:        "/auth/whoami",
					contentType: "application/json",
					headers: map[string]string{
						"Accept": "application/json",
					},
				},
			},
			want: map[string]interface{}{
				"response": requests.Response{
					RedirectTokenName: "AUTHP_REDIRECT_URL",
					Authenticated:     true,
				},
				"status_code":  http.StatusOK,
				"content_type": "application/json",
			},
		},
		{
			name: "test authenticated user accessing css static asset",
			// disabled: true,
			auth: &testAuthRequest{
				endpoint: "/auth/login",
				username: tests.TestUser1,
				password: tests.TestPwd1,
				realm:    "localize",
			},
			requests: []*testAppRequest{
				{
					method: "GET",
					path:   "/auth/assets/css/styles.css",
				},
			},
			want: map[string]interface{}{
				"response": requests.Response{
					RedirectTokenName: "AUTHP_REDIRECT_URL",
					Authenticated:     true,
				},
				"status_code":  http.StatusOK,
				"content_type": "text/css",
			},
		},
		{
			name: "test authenticated user accessing favicon static asset",
			// disabled: true,
			auth: &testAuthRequest{
				endpoint: "/auth/login",
				username: tests.TestUser1,
				password: tests.TestPwd1,
				realm:    "localize",
			},
			requests: []*testAppRequest{
				{
					method: "GET",
					path:   "/favicon.png",
				},
			},
			want: map[string]interface{}{
				"response": requests.Response{
					RedirectTokenName: "AUTHP_REDIRECT_URL",
					Authenticated:     true,
				},
				"status_code":  http.StatusOK,
				"content_type": "image/png",
			},
		},
		{
			name: "test unauthenticated user accessing default portal page",
			requests: []*testAppRequest{
				{
					method: "GET",
					path:   "/portal",
				},
			},
			want: map[string]interface{}{
				"response": requests.Response{
					RedirectTokenName: "AUTHP_REDIRECT_URL",
				},
				"status_code":  http.StatusFound,
				"content_type": "",
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disabled {
				return
			}
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			got := make(map[string]interface{})
			// Create test HTTP server.
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := context.Background()
				rr := requests.NewRequest()
				err := portal.ServeHTTP(ctx, w, r, rr)
				if tests.EvalErrWithLog(t, err, tc.want, tc.shouldErr, tc.err, msgs) {
					return
				}
				got["response"] = rr.Response
			}))
			defer ts.Close()

			cert, err := x509.ParseCertificate(ts.TLS.Certificates[0].Certificate[0])
			if err != nil {
				if tests.EvalErrWithLog(t, errors.ErrGeneric.WithArgs("failed extracting server certs", err), tc.want, tc.shouldErr, tc.err, msgs) {
					return
				}
			}
			cp := x509.NewCertPool()
			cp.AddCert(cert)

			cj, err := cookiejar.New(nil)
			if err != nil {
				if tests.EvalErrWithLog(t, errors.ErrGeneric.WithArgs("failed adding cookie jar", err), tc.want, tc.shouldErr, tc.err, msgs) {
					return
				}
			}
			client := http.Client{
				Jar:     cj,
				Timeout: time.Second * 10,
				Transport: &http.Transport{
					Dial: (&net.Dialer{
						Timeout: 5 * time.Second,
					}).Dial,
					TLSHandshakeTimeout: 5 * time.Second,
					TLSClientConfig: &tls.Config{
						RootCAs: cp,
					},
				},
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					// Do not follow redirects.
					return http.ErrUseLastResponse
				},
			}

			// Authenticate.
			if tc.auth != nil {
				msgs = append(msgs, fmt.Sprintf("Endpoint and content type %s %s", tc.auth.endpoint, tc.auth.contentType))
				switch tc.auth.contentType {
				case "application/json":
					params := &AuthRequest{
						Username: tc.auth.username,
						Password: tc.auth.password,
						Realm:    tc.auth.realm,
					}
					b, _ := json.Marshal(params)
					req, _ := http.NewRequest("POST", ts.URL+tc.auth.endpoint, bytes.NewReader(b))
					req.Header.Set("Accept", tc.auth.contentType)
					resp, err := client.Do(req)
					if err != nil {
						if tests.EvalErrWithLog(t, errors.ErrGeneric.WithArgs("failed auth request", err), tc.want, tc.shouldErr, tc.err, msgs) {
							return
						}
					}
					respBody, err := ioutil.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil {
						if tests.EvalErrWithLog(t, errors.ErrGeneric.WithArgs("failed reading auth request body", err), tc.want, tc.shouldErr, tc.err, msgs) {
							return
						}
					}
					if bytes.Contains(respBody, []byte(`"error":`)) {
						if tests.EvalErrWithLog(t, errors.ErrGeneric.WithArgs("failed authentication request", respBody), tc.want, tc.shouldErr, tc.err, msgs) {
							return
						}
					}
				default:
					// The use of url.Values is equivalent to using
					// `strings.NewReader("username=webadmin&password=password123&realm=local")`
					params := url.Values{}
					params.Set("username", tc.auth.username)
					params.Set("password", tc.auth.password)
					params.Set("realm", tc.auth.realm)
					req, err := http.NewRequest("POST", ts.URL+tc.auth.endpoint, strings.NewReader(params.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					req.Header.Set("Content-Length", strconv.Itoa(len(params.Encode())))
					resp, err := client.Do(req)
					if err != nil {
						t.Fatalf("failed authentication request: %v", err)
					}
					bearer := resp.Header.Get("Authorization")
					if !strings.HasPrefix(bearer, "Bearer") {
						t.Fatalf("failed authentication request: bearer header not found")
					}
					msgs = append(msgs, fmt.Sprintf("auth response: %s", bearer))
				}
			}

			// Process HTTP Requests.
			for i, r := range tc.requests {
				var pr string
				if len(tc.requests) > 1 {
					pr = fmt.Sprintf("req%02d_", i+1)
				}
				req, err := http.NewRequest(r.method, ts.URL+r.path, nil)
				if err != nil {
					got[pr+"error"] = err
					continue
				}

				msgs = append(msgs, fmt.Sprintf("HTTP %s %s", r.method, ts.URL+r.path))
				if len(r.headers) > 0 {
					for k, v := range r.headers {
						req.Header.Add(k, v)
					}
				}
				if len(r.query) > 0 {
					q := req.URL.Query()
					for k, v := range r.query {
						q.Set(k, v)
					}
					req.URL.RawQuery = q.Encode()
				}

				resp, err := client.Do(req)
				if err != nil {
					got[pr+"error"] = fmt.Sprintf("failed request: %v", err)
				}
				body, err := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					got[pr+"error"] = fmt.Sprintf("failed  reading response: %v", err)
				}

				got[pr+"status_code"] = resp.StatusCode
				got[pr+"content_type"] = resp.Header.Get("Content-Type")
				switch resp.Header.Get("Content-Type") {
				case "image/png":
				default:
					msgs = append(msgs, fmt.Sprintf("response body: %s", body))
				}
				switch {
				case bytes.HasPrefix(body, []byte(`{`)):
					switch {
					case bytes.Contains(body, []byte(`"error":`)):
						b := &AccessDeniedResponse{}
						json.Unmarshal(body, b)
						got[pr+"message"] = b.Message
					}
				}
			}
			tests.EvalObjectsWithLog(t, "response", tc.want, got, msgs)
		})
	}
}
