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
	port := "8080"
	securePort := "8443"
	authPath := "auth"
	hostPort := host + ":" + securePort
	baseURL := scheme + "://" + hostPort
	accessTokenName := "access_token"
	tokenSecret := "0e2fdcf8-6868-41a7-884b-7308795fc286"
	tokenIssuer := "e1008f2d-ccfa-4e62-bbe6-c202ec2988cc"
	localhost, _ := url.Parse(baseURL)
	tester := caddytest.NewTester(t)
	tester.InitServer(`
    {
      http_port     `+port+`
      https_port    `+securePort+`
    }

    `+hostPort+` {
	  route /`+authPath+`* {
        auth_portal {
          path /`+authPath+`
          backends {
            local_backend {
              method local
              path assets/conf/local/auth/user_db.json
              realm local
            }
          }
          jwt {
            token_name access_token
            token_secret `+tokenSecret+`
            token_issuer `+tokenIssuer+`
          }
          ui {
            login_template "assets/conf/local/ui/login.template"
            portal_template "assets/conf/local/ui/portal.template"
            whoami_template "assets/conf/local/ui/whoami.template"
            logo_url "https://caddyserver.com/resources/images/caddy-circle-lock.svg"
            logo_description "Caddy"
            links {
              "Public Access" /public
			  "Private Access" /private
            }
          }
        }
      }

      route /public* {
        respond * "public" 200
      }

      route {
        redir https://{hostport}/auth 302
      }
    }
    `, "caddyfile")

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
