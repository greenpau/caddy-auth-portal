package portal

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestCaddyfile(t *testing.T) {
	scheme := "http"
	host := "localhost"
	port := "8080"
	securePort := "8443"
	authPath := "auth"
	hostPort := host + ":" + port
	baseURL := scheme + "://" + hostPort
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
              type local
              path /etc/gatekeeper/auth/local/users.json
              realm local
            }
          }
          jwt {
            token_name access_token
            token_secret `+tokenSecret+`
            token_issuer `+tokenIssuer+`
          }
          ui {
            login_template "/etc/gatekeeper/ui/forms_login.template"
            portal_template "/etc/gatekeeper/ui/forms_portal.template"
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

	cookies := []*http.Cookie{}
	cookie := &http.Cookie{
		Name:  "access_token",
		Value: "anonymous",
	}
	cookies = append(cookies, cookie)
	tester.Client.Jar.SetCookies(localhost, cookies)
	// tester.AssertGetResponse(baseURL+"/auth/whoami?content_type=plaintext&field=username", 400, "greenpau")
	//tester.AssertResponseCode(baseURL+"/auth/whoami?content_type=plaintext&field=username", 400)

	req, _ := http.NewRequest("POST", baseURL+"/"+authPath, strings.NewReader("username=webadmin&password=password123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := tester.AssertResponseCode(req, 200)
	t.Logf("%v", resp)
	time.Sleep(1 * time.Second)
}
