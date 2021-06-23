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

package ui

// PageTemplates stores UI templates.
var PageTemplates = map[string]string{
	"basic/login": `<!doctype html>
<html lang="en">
  <head>
    <title>{{ .Title }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Authentication Portal">
    <meta name="author" content="Paul Greenberg github.com/greenpau">
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">

    <!-- Matrialize CSS -->
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/materialize-css/css/materialize.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/styles.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
  </head>
  <body class="app-body">
    <div class="container">
      <div class="row">
        <div class="col s12 m8 offset-m2 l6 offset-l3 xl4 offset-xl4 app-card-container">
          <div class="row app-header center">
            {{ if .LogoURL }}
            <div class="col s4">
              <img class="d-block mx-auto mb-2" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" width="72" height="72">
            </div>
            <div class="col s8">
              <h4>{{ .Title }}</h4>
            </div>
            {{ else }}
              <h4>{{ .Title }}</h4>
            {{ end }}
          </div>
          {{ if eq .Data.login_options.form_required "yes" }}
          <form action="{{ pathjoin .ActionEndpoint "/login" }}" method="POST">
            <div class="row app-form">
              {{ if eq .Data.login_options.username_required "yes" }}
              <div class="row app-input-row valign-wrapper">
                <div class="col s4">
                  <p class="app-input-text">Username</p>
                </div>
                <div class="col s8">
                  <div class="input-field app-input-field">
                    <input id="username" name="username" type="text" class="validate" autocorrect="off" autocapitalize="off" required />
                  </div>
                </div>
              </div>
              {{ end }}
              {{ if eq .Data.login_options.password_required "yes" }}
              <div class="row app-input-row valign-wrapper">
                <div class="col s4">
                  <p class="app-input-text">Password</p>
                </div>
                <div class="col s8">
                  <div class="input-field app-input-field">
                    <input id="password" name="password" type="password" class="validate" autocorrect="off" autocapitalize="off" required />
                  </div>
                </div>
              </div>
              {{ end }}
              {{ if eq .Data.login_options.realm_dropdown_required "yes" }}
              <div class="row app-input-row valign-wrapper">
                <div class="col s4">
                  <p class="app-input-text">Domain</p>
                </div>
                <div class="col s8">
                  <div class="input-field app-input-field">
                    <select id="realm" name="realm" class="browser-default">
                    {{ range .Data.login_options.realms }}
                      {{ if eq .default "yes" }}
                      <option value="{{ .realm }}" selected>{{ .label }}</option>
                      {{ else }}
                      <option value="{{ .realm }}">{{ .label }}</option>
                      {{ end }}
                    {{ end }}
                    </select>
                  </div>
	              </div>
	            </div>
              {{ else }}
                {{ range .Data.login_options.realms }}
                  <input type="hidden" id="realm" name="realm" value="{{ .realm }}" />
                {{ end }}
              {{ end }}
            </div>
            <div class="row app-control valign-wrapper">
              <div class="col s6">
                {{ if eq .Data.login_options.registration_required "yes" }}
                <span class="app-link"><a href="{{ pathjoin .ActionEndpoint "/register" }}">Register</a></span>
                {{ end }}
                {{ if eq .Data.login_options.password_recovery_required "yes" }}
                <span class="app-link"><a href="{{ pathjoin .ActionEndpoint "/forgot" }}">Forgot Password?</a></span>
                {{ end }}
              </div>
              <div class="col s6 right-align">
                <button type="submit" name="submit" class="waves-effect waves-light btn app-btn">
                  <i class="las la-sign-in-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Login</span>
                </button>
              </div>
            </div>
          </form>
          {{ end }}
          {{ if eq .Data.login_options.external_providers_required "yes" }}
          <div class="row">
            {{ if eq .Data.login_options.username_required "yes" }}
            <p class="app-text">Additional Sign In Options:</p>
            {{end}}
            {{ range .Data.login_options.external_providers }}
            <a class="waves-effect waves-light {{ .color }} app-btn btn" href="{{ .endpoint }}">
              <i class="lab la-{{ .icon }} app-btn-icon"></i><span class="app-btn-text">{{ .text }}</span>
            </a>
            {{ end }}
          </div>
          {{ end }}
        </div>
      </div>
    </div>
    <!-- Optional JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/materialize-css/js/materialize.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
    {{ if .Message }}
    <script>
    var toastHTML = '<span class="app-error-text">{{ .Message }}</span><button class="btn-flat toast-action" onclick="M.Toast.dismissAll();">Close</button>';
    toastElement = M.toast({
      html: toastHTML,
      classes: 'toast-error'
    });
    const appContainer = document.querySelector('.app-card-container')
    appContainer.prepend(toastElement.el)
    </script>
    {{ end }}
  </body>
</html>`,
	"basic/portal": `<!doctype html>
<html lang="en">
  <head>
    <title>{{ .Title }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Authentication Portal">
    <meta name="author" content="Paul Greenberg github.com/greenpau">
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">
    <!-- Matrialize CSS -->
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/materialize-css/css/materialize.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/styles.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
  </head>
  <body class="app-body">
    <div class="container">
      <div class="row">
        <div class="col s12 m6 offset-m3 l4 offset-l4 app-card-container">
          <div class="row app-header center">
            {{ if .LogoURL }}
            <div class="col">
              <img class="d-block mx-auto mb-2" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" width="72" height="72">
            </div>
            <div class="col">
              <h4>{{ .Title }}</h4>
            </div>
            {{ else }}
              <h4>{{ .Title }}</h4>
            {{ end }}
          </div>
          <div class="row">
            <p class="app-text">Access the following services.</p>
            <ul class="collection">
              {{range .PrivateLinks}}
              <li class="collection-item">
                {{ if .IconEnabled -}}
                <i class="{{ .IconName }}"></i>
                {{- end }}
                <a href="{{ .Link }}"{{ if .TargetEnabled }} target="{{ .Target }}"{{ end }}>{{ .Title }}</a>
              </li>
              {{ end }}
            </ul>
          </div>
          <div class="row right">
            <a href="{{ pathjoin .ActionEndpoint "/logout" }}" class="navbtn-last">
              <button type="button" class="waves-effect waves-light btn navbtn active navbtn-last app-btn">
                <i class="las la-sign-out-alt left app-btn-icon"></i>
                <span class="app-btn-text">Logout</span>
              </button>
            </a>
          </div>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/materialize-css/js/materialize.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
    {{ if .Message }}
    <script>
    var toastHTML = '<span>{{ .Message }}</span><button class="btn-flat toast-action" onclick="M.Toast.dismissAll();">Close</button>';
    toastElement = M.toast({
      html: toastHTML,
      classes: 'toast-error'
    });
    const appContainer = document.querySelector('.app-card-container')
    appContainer.prepend(toastElement.el)
    </script>
    {{ end }}
  </body>
</html>`,
	"basic/whoami": `<!doctype html>
<html lang="en">
  <head>
    <title>{{ .Title }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Authentication Portal">
    <meta name="author" content="Paul Greenberg github.com/greenpau">
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">
    <!-- Matrialize CSS -->
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/materialize-css/css/materialize.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/highlight.js/css/atom-one-dark.min.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/styles.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
  </head>
  <body class="app-body">
    <div class="container">
      <div class="row">
        <div class="col s12 m12 l6 offset-l3 app-card-container">
          <div class="row app-header center">
            {{ if .LogoURL }}
            <div class="col">
              <img class="d-block mx-auto mb-2" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" width="72" height="72">
            </div>
            <div class="col">
              <h4>{{ .Title }}</h4>
            </div>
            {{ else }}
              <h4>{{ .Title }}</h4>
            {{ end }}
          </div>
          <div class="row">
	          <pre><code class="language-json hljs">{{ .Data.token }}</code></pre>
          </div>
          <div class="row right">
            <a href="{{ pathjoin .ActionEndpoint "/portal" }}">
              <button type="button" class="btn waves-effect waves-light navbtn active">
                <i class="las la-home left app-btn-icon"></i>
                <span class="app-btn-text">Portal</span>
              </button>
            </a>
            <a href="{{ pathjoin .ActionEndpoint "/logout" }}" class="navbtn-last">
              <button type="button" class="btn waves-effect waves-light navbtn active navbtn-last">
                <i class="las la-sign-out-alt left app-btn-icon"></i>
                <span class="app-btn-text">Logout</span>
              </button>
            </a>
          </div>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/materialize-css/js/materialize.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/highlight.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/languages/json.min.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
    <script>
    hljs.initHighlightingOnLoad();
    </script>
  </body>
</html>`,
	"basic/register": `<!doctype html>
<html lang="en">
  <head>
    <title>{{ .Title }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Authentication Portal">
    <meta name="author" content="Paul Greenberg github.com/greenpau">
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">

		<!-- Matrialize CSS -->
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/materialize-css/css/materialize.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/styles.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
  </head>
  <body class="app-body">
    <div class="container">
      <div class="row">
        <div class="col s12 m12 l6 offset-l3 registration-container">
          {{ if not .Data.registered }}
          <form action="{{ pathjoin .ActionEndpoint "/register" }}" method="POST">
          {{ end }}
          <div class="card card-large app-card">
            <div class="card-content">
              <span class="card-title center-align">
                <div class="section app-header">
                  {{ if .LogoURL }}
                  <img class="d-block mx-auto mb-2" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" width="72" height="72">
                  {{ end }}
                  <h4>{{ .Title }}</h4>
                </div>
              </span>
              {{ if not .Data.registered }}
              <div class="input-field">
                <input id="username" name="username" type="text" class="validate"
                  pattern="{{ .Data.username_validate_pattern }}"
                  title="{{ .Data.username_validate_title }}"
                  required />
                <label for="username">Username</label>
              </div>
              <div class="input-field">
                <input id="email" name="email" type="email" class="validate"
                  required />
                <label for="email">Email Address</label>
              </div>
              <div class="input-field">
                <input id="password" name="password" type="password" class="validate"
                  pattern="{{ .Data.password_validate_pattern }}"
                  title="{{ .Data.password_validate_title }}"
                  required />
                <label for="password">Password</label>
              </div>
              <div class="input-field">
                <input id="password_confirm" name="password_confirm" type="password" class="validate"
                  pattern="{{ .Data.password_validate_pattern }}"
                  title="{{ .Data.password_validate_title }}"
                  required />
                <label for="password_confirm">Confirm Password</label>
              </div>
              {{ if .Data.require_registration_code }}
              <div class="input-field">
                <input id="code" name="code" type="text" class="validate" required />
                <label for="code">Registration Code</label>
              </div>
              {{ end }}
              {{ if .Data.require_accept_terms }}
              <p>
                <label>
                  <input type="checkbox" id="accept_terms" name="accept_terms" required />
                  <span>I agree to
                    <a href="{{ .Data.terms_conditions_link }}" target="_blank">Terms and Conditions</a> and
                    <a href="{{ .Data.privacy_policy_link }}" target="_blank">Privacy Policy</a>.
                  </span>
                </label>
              </p>
              {{ end }}
              {{ else }}
              <p class="app-text">Thank you for registering and we hope you enjoy the experience!</p>
              <p class="app-text">Here are a few things to keep in mind:</p>
              <ol class="app-text">
                <li>You should receive your confirmation email within the next 15 minutes.</li>
                <li>If you still don't see it, please email support so we can resend it to you.</li>
              </ol>
              {{ end }}
            </div>
            <div class="card-action right-align">
              {{ if not .Data.registered }}
              <a href="{{ .ActionEndpoint }}" class="navbtn-last">
                <button type="button" class="waves-effect waves-light btn navbtn active navbtn-last app-btn">
                  <i class="las la-undo left app-btn-icon"></i>
                  <span class="app-btn-text">Back</span>
                </button>
              </a>
              <button type="submit" name="submit" class="waves-effect waves-light btn navbtn active navbtn-last app-btn">
                <i class="las la-chevron-circle-right app-btn-icon"></i>
                <span class="app-btn-text">Submit</span>
              </button>
              {{ else }}
              <a href="{{ .ActionEndpoint }}" class="navbtn-last">
                <button type="button" class="waves-effect waves-light btn navbtn active navbtn-last app-btn">
                  <i class="las la-home left app-btn-icon"></i>
                  <span class="app-btn-text">Portal</span>
                </button>
              </a>
              {{ end }}
            </div>
          </div>
          </form>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/materialize-css/js/materialize.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
    {{ if .Message }}
    <script>
    var toastHTML = '<span>{{ .Message }}</span><button class="btn-flat toast-action" onclick="M.Toast.dismissAll();">Close</button>';
    toastElement = M.toast({
      html: toastHTML,
      classes: 'toast-error',
      displayLength: 10000
    });
    const appContainer = document.querySelector('.registration-container')
    appContainer.prepend(toastElement.el)
    </script>
    {{ end }}
  </body>
</html>`,
	"basic/generic": `<!doctype html>
<html lang="en">
  <head>
    <title>{{ .Title }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Authentication Portal">
    <meta name="author" content="Paul Greenberg github.com/greenpau">
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">

    <!-- Matrialize CSS -->
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/materialize-css/css/materialize.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/styles.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
  </head>
  <body class="app-body">
    <div class="container">
      <div class="row">
        <div class="col s12 m12 l6 offset-l3">
          <div class="card card-large app-card">
            <div class="card-content">
              <span class="card-title center-align">
                <div class="section app-header">
                  {{ if .LogoURL }}
                  <a href="{{ pathjoin .ActionEndpoint }}">
                    <img class="d-block mx-auto mb-2" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" width="72" height="72">
                  </a>
                  {{ end }}
                  <h4>{{ .Title }}</h4>
                </div>
              </span>
            </div>
            <div class="card-action right-align">
              {{ if .Data.go_back_url }}
              <a href="{{ .Data.go_back_url }}" class="navbtn-last">
                <button type="button" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                  <i class="las la-undo left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
              {{ end }}
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/materialize-css/js/materialize.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
  </body>
</html>`,
	"basic/settings": `<!doctype html>
<html lang="en">
  <head>
    <title>{{ .Title }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <meta name="description" content="Authentication Portal">
    <meta name="author" content="Paul Greenberg github.com/greenpau">
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">

    <!-- Matrialize CSS -->
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/materialize-css/css/materialize.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    {{ if or (eq .Data.view "mfa-add-app") (eq .Data.view "mfa-test-app") }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/montserrat.css" }}" />
    {{ end }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    {{ if or (eq .Data.view "sshkeys-add") (eq .Data.view "gpgkeys-add") (eq .Data.view "sshkeys-view") (eq .Data.view "gpgkeys-view") }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/highlight.js/css/atom-one-dark.min.css" }}" />
    {{ end }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/styles.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
    {{ if or (eq .Data.view "mfa-add-app") (eq .Data.view "mfa-test-app") }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/mfa_app.css" }}" />
    {{ end }}
  </head>
  <body class="app-body">
    <div class="container app-container">
      <div class="row">
        <nav>
          <div class="nav-wrapper">
            {{ if .LogoURL }}
            <img src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" />
            {{ end }}
            <a href="#" class="brand-logo">{{ .Title }}</a>
            <ul id="nav-mobile" class="right hide-on-med-and-down">
              <li>
                <a href="{{ pathjoin .ActionEndpoint "/portal" }}">
                  <button type="button" class="btn waves-effect waves-light navbtn active">
                    <span class="app-btn-text">Portal</span>
                    <i class="las la-home left app-btn-icon app-navbar-btn-icon"></i>
                 </button>
                </a>
              </li>
              <li>
                <a href="{{ pathjoin .ActionEndpoint "/logout" }}" class="navbtn-last">
                  <button type="button" class="btn waves-effect waves-light navbtn active navbtn-last">
                    <span class="app-btn-text">Logout</span>
                    <i class="las la-sign-out-alt left app-btn-icon app-navbar-btn-icon"></i>
                  </button>
                </a>
              </li>
            </ul>
          </div>
        </nav>
      </div>
      <div class="row">
        <div class="col s12 l3">
          <div class="collection">
            <a href="{{ pathjoin .ActionEndpoint "/settings/" }}" class="collection-item{{ if eq .Data.view "general" }} active{{ end }}">General</a>
            <a href="{{ pathjoin .ActionEndpoint "/settings/sshkeys" }}" class="collection-item{{ if eq .Data.view "sshkeys" }} active{{ end }}">SSH Keys</a>
            <a href="{{ pathjoin .ActionEndpoint "/settings/gpgkeys" }}" class="collection-item{{ if eq .Data.view "gpgkeys" }} active{{ end }}">GPG Keys</a>
            <a href="{{ pathjoin .ActionEndpoint "/settings/apikeys" }}" class="collection-item{{ if eq .Data.view "apikeys" }} active{{ end }}">API Keys</a>
            <a href="{{ pathjoin .ActionEndpoint "/settings/mfa" }}" class="collection-item{{ if eq .Data.view "mfa" }} active{{ end }}">MFA</a>
            <a href="{{ pathjoin .ActionEndpoint "/settings/password" }}" class="collection-item{{ if eq .Data.view "password" }} active{{ end }}">Password</a>
            <a href="{{ pathjoin .ActionEndpoint "/settings/misc" }}" class="collection-item{{ if eq .Data.view "misc" }} active{{ end }}">Miscellaneous</a>
            <a href="{{ pathjoin .ActionEndpoint "/portal" }}" class="hide-on-med-and-up collection-item">Portal</a>
            <a href="{{ pathjoin .ActionEndpoint "/logout" }}" class="hide-on-med-and-up collection-item">Logout</a>
          </div>
        </div>
        <div class="col s12 l9 app-content">
          {{ if eq .Data.view "general" }}
            <p>The {{ .Data.view }} view is under construction.</p>
          {{ end }}
          {{ if eq .Data.view "sshkeys" }}
          <div class="row right">
            <div class="col s12 right">
              <a href="{{ pathjoin .ActionEndpoint "/settings/sshkeys/add" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active app-btn">
                  <i class="las la-key left app-btn-icon"></i>
                  <span class="app-btn-text">Add SSH Key</span>
                </button>
              </a>
            </div>
          </div>
          <div class="row">
            <div class="col s12">
            {{ if .Data.sshkeys }}
              {{range .Data.sshkeys}}
              <div class="card">
                <div class="card-content">
                  <span class="card-title">{{ .Comment }}</span>
                  <p>
                    <b>ID</b>: {{ .ID }}<br/>
                    <b>Type:</b> {{ .Type }}<br/>
                    <b>Fingerprint (SHA256)</b>: {{ .Fingerprint }}<br/>
                    <b>Fingerprint (MD5)</b>: {{ .FingerprintMD5 }}<br/>
                    <b>Created At</b>: {{ .CreatedAt }}
                  </p>
                </div>
                <div class="card-action">
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/sshkeys/delete" .ID }}">Delete</a>
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/sshkeys/view" .ID }}">View</a>
                </div>
              </div>
              {{ end }}
            {{ else }}
              <p>No registered SSH Keys found</p>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "sshkeys-add" }}
            <form action="{{ pathjoin .ActionEndpoint "/settings/sshkeys/add" }}" method="POST">
              <div class="row">
                <div class="col s12">
                  <h1>Add SSH Key</h1>
                  <p>Please paste your public SSH key here.</p>
                  <div class="input-field shell-textarea-wrapper">
                    <textarea id="key1" name="key1" class="hljs shell-textarea"></textarea>
                  </div>
                  <div class="input-field">
                    <input placeholder="Comment" name="comment1" id="comment1" type="text" autocorrect="off" autocapitalize="off" autocomplete="off" class="validate">
                  </div>
                  <div class="right">
                    <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                      <i class="las la-plus-circle left app-btn-icon"></i>
                      <span class="app-btn-text">Add SSH Key</span>
                    </button>
                  </div>
                </div>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "sshkeys-add-status" }}
          <div class="row">
            <div class="col s12">
            {{ if eq .Data.status "SUCCESS" }}
              <h1>Public SSH Key</h1>
              <p>{{ .Data.status_reason }}</p>
              <a href="{{ pathjoin .ActionEndpoint "/settings/sshkeys" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            {{ else }}
              <h1>Public SSH Key</h1>
              <p>Reason: {{ .Data.status_reason }} </p>
              <a href="{{ pathjoin .ActionEndpoint "/settings/sshkeys/add" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "sshkeys-delete-status" }}
          <div class="row">
            <div class="col s12">
            <h1>Public SSH Key</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            <a href="{{ pathjoin .ActionEndpoint "/settings/sshkeys" }}">
              <button type="button" class="btn waves-effect waves-light navbtn active">
                <i class="las la-undo-alt left app-btn-icon"></i>
                <span class="app-btn-text">Go Back</span>
              </button>
            </a>
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "gpgkeys" }}
          <div class="row right">
            <div class="col s12 right">
              <a href="{{ pathjoin .ActionEndpoint "/settings/gpgkeys/add" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active app-btn">
                  <i class="las la-key left app-btn-icon"></i>
                  <span class="app-btn-text">Add GPG Key</span>
                </button>
              </a>
            </div>
          </div>
          <div class="row">
            <div class="col s12">
            {{ if .Data.gpgkeys }}
              {{range .Data.gpgkeys}}
              <div class="card">
                <div class="card-content">
                  <span class="card-title">{{ .Comment }}</span>
                  <p>
                    <b>ID</b>: {{ .ID }}<br/>
                    <b>Usage:</b> {{ .Usage }}<br/>
                    <b>Type:</b> {{ .Type }}<br/>
                    <b>Fingerprint</b>: {{ .Fingerprint }}<br/>
                    <b>Created At</b>: {{ .CreatedAt }}
                  </p>
                </div>
                <div class="card-action">
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/gpgkeys/delete" .ID }}">Delete</a>
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/gpgkeys/view" .ID }}">View</a>
                </div>
              </div>
              {{ end }}
            {{ else }}
              <p>No registered GPG Keys found</p>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "gpgkeys-add" }}
            <form action="{{ pathjoin .ActionEndpoint "/settings/gpgkeys/add" }}" method="POST">
              <div class="row">
                <div class="col s12">
                  <h1>Add GPG Key</h1>
                  <p>Please paste your public GPG key here.</p>
                  <div class="input-field shell-textarea-wrapper">
                      <textarea id="key1" name="key1" class="hljs shell-textarea"></textarea>
                  </div>
                  <div class="input-field">
                    <input placeholder="Comment" name="comment1" id="comment1" type="text" autocorrect="off" autocapitalize="off" autocomplete="off" class="validate">
                  </div>
                  <div class="right">
                    <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                      <i class="las la-plus-circle left app-btn-icon"></i>
                      <span class="app-btn-text">Add GPG Key</span>
                    </button>
                  </div>
                </div>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "gpgkeys-add-status" }}
          <div class="row">
            <div class="col s12">
            {{ if eq .Data.status "SUCCESS" }}
              <h1>Public GPG Key</h1>
              <p>{{ .Data.status_reason }}</p>
              <a href="{{ pathjoin .ActionEndpoint "/settings/gpgkeys" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            {{ else }}
              <h1>Public GPG Key</h1>
              <p>Reason: {{ .Data.status_reason }} </p>
              <a href="{{ pathjoin .ActionEndpoint "/settings/gpgkeys/add" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "gpgkeys-delete-status" }}
          <div class="row">
            <div class="col s12">
            <h1>Public GPG Key</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            <a href="{{ pathjoin .ActionEndpoint "/settings/gpgkeys" }}">
              <button type="button" class="btn waves-effect waves-light navbtn active">
                <i class="las la-undo-alt left app-btn-icon"></i>
                <span class="app-btn-text">Go Back</span>
              </button>
            </a>
            </div>
          </div>
          {{ end }}
          {{ if or (eq .Data.view "sshkeys-view") (eq .Data.view "gpgkeys-view") }}
          <div class="row">
            <div class="col s12">
              {{ if eq .Data.view "gpgkeys-view" }}
              <h1>GPG Key</h1>
              {{ else }}
              <h1>SSH Key</h1>
              {{ end }}
              <pre><code class="language-json hljs">{{ .Data.key }}</code></pre>
              {{ if .Data.pem_key }}
              <h5>PEM</h5>
              <pre><code class="language-text hljs">{{ .Data.pem_key }}</code></pre>
              {{ end }}
              {{ if .Data.openssh_key }}
              <h5>OpenSSH</h5>
              <pre><code class="language-text hljs">{{ .Data.openssh_key }}</code></pre>
              {{ end }}
              {{ if eq .Data.view "gpgkeys-view" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/gpgkeys" }}">
              {{ else }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/sshkeys" }}">
              {{ end }}
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "apikeys" }}
          <div class="row">
            <div class="col s12">
              <a href="{{ pathjoin .ActionEndpoint "/settings/apikeys/add" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active app-btn">
                  <i class="las la-key left app-btn-icon"></i>
                  <span class="app-btn-text">Add API Key</span>
                </button>
              </a>
            </div>
          </div>
          <div class="row">
            <div class="col s12">
            {{ if .Data.api_keys }}
              <p>List of registered API Keys</p>
            {{ else }}
              <p>No registered API Keys found</p>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "mfa" }}
          <div class="row right">
            <div class="col s12 right">
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa/add/app" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active app-btn">
                  <i class="las la-mobile-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Add MFA App</span>
                </button>
              </a>
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa/add/u2f" }}" class="navbtn-last">
                <button type="button" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                  <i class="las la-key left app-btn-icon"></i>
                  <span class="app-btn-text">Add U2F Key</span>
                </button>
              </a>
            </div>
          </div>
          <div class="row">
            <div class="col s12">
            {{ if .Data.mfa_tokens }}
              {{range .Data.mfa_tokens}}
              <div class="card">
                <div class="card-content">
                  <span class="card-title">{{ .Comment }}</span>
                  <p>
                    <b>ID</b>: {{ .ID }}<br/>
                    {{ if eq .Type "u2f" }}
                    <b>Type</b>: Hardware/U2F Token<br/>
                    {{ else }}
                    <b>Type</b>: Authenticator App<br/>
                    <b>Algorithm</b>: {{ .Algorithm }}<br/>
                    <b>Period</b>: {{ .Period }} seconds<br/>
                    <b>Digits</b>: {{ .Digits }}<br/>
                    {{ end }}
                    <b>Created At</b>: {{ .CreatedAt }}
                  </p>
                </div>
                <div class="card-action">
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/mfa/delete/" .ID }}">Delete</a>
                  {{ if eq .Type "totp" }}
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/mfa/test/app/" (printf "%d" .Digits) .ID }}">Test</a>
                  {{ end }}
                  {{ if eq .Type "u2f" }}
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/mfa/test/u2f/generic" .ID }}">Test</a>
                  {{ end }}
                </div>
              </div>
              {{ end }}
            {{ else }}
              <p>No registered MFA devices found</p>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "mfa-add-app" }}
            <form id="mfa-add-app-form" action="{{ pathjoin .ActionEndpoint "/settings/mfa/add/app" }}" method="POST">
              <div class="row">
                <h1>Add MFA Authenticator Application</h1>
                <div class="col s12 m11 l11">
                  <div id="token-params">
                    <h6 id="token-params-mode" class="hide">Token Parameters</h6>
                    <p><b>Step 1</b>: Amend the label and comment associated with the authenticator.
                      The label is what you would see in your authenticator app.
                      The comment is what you would see in this portal.
                    </p>
                    <div class="input-field">
                      <input id="label" name="label" type="text" class="validate" pattern="[A-Za-z0-9 -]{4,25}"
                        title="Authentication code should contain 4-25 characters and consists of A-Z, a-z, 0-9, space, and dash characters."
                        maxlength="25"
                        autocorrect="off" autocapitalize="off" autocomplete="off"
                        value="{{ .Data.mfa_label }}"
                        required />
                      <label for="label">Label</label>
                    </div>
                    <div class="input-field">
                      <input id="comment" name="comment" type="text" class="validate" pattern="[A-Za-z0-9 -]{4,25}"
                        title="Authentication code should contain 4-25 characters and consists of A-Z, a-z, 0-9, space, and dash characters."
                        maxlength="25"
                        autocorrect="off" autocapitalize="off" autocomplete="off"
                        value="{{ .Data.mfa_comment }}"
                        required />
                      <label for="comment">Comment</label>
                    </div>
                    <p><b>Step 1a</b> (<i>optional</i>): If necessary, click
                      <a href="#advanced-setup-mode" onclick="toggleAdvancedSetupMode()">here</a> to customize default values.
                    </p>
                    <div id="advanced-setup-all" class="hide">
                      <h6 id="advanced-setup-mode" class="hide">Advanced Setup Mode</h6>
                      <div id="advanced-setup-secret" class="input-field">
                        <input id="secret" name="secret" type="text" class="validate" pattern="[A-Za-z0-9]{10,100}"
                          title="Token secret should contain 10-200 characters and consists of A-Z and 0-9 characters only."
                          autocorrect="off" autocapitalize="off" autocomplete="off"
                          maxlength="100"
                          value="{{ .Data.mfa_secret }}"
                          required />
                        <label for="secret">Token Secret</label>
                      </div>
                      <div id="advanced-setup-period" class="input-field">
                        <select id="period" name="period" class="browser-default">
                          <option value="15" {{ if eq .Data.mfa_period "15" }} selected{{ end }}>15 Seconds Lifetime</option>
                          <option value="30" {{ if eq .Data.mfa_period "30" }} selected{{ end }}>30 Seconds Lifetime</option>
                          <option value="60" {{ if eq .Data.mfa_period "60" }} selected{{ end }}>60 Seconds Lifetime</option>
                          <option value="90" {{ if eq .Data.mfa_period "90" }} selected{{ end }}>90 Seconds Lifetime</option>
                        </select>
                      </div>
                      <div id="advanced-setup-digits" class="input-field">
                        <select id="digits" name="digits" class="browser-default">
                          <option value="4" {{ if eq .Data.mfa_digits "4" }} selected{{ end }}>4 Digit Code</option>
                          <option value="6" {{ if eq .Data.mfa_digits "6" }} selected{{ end }}>6 Digit Code</option>
                          <option value="8" {{ if eq .Data.mfa_digits "8" }} selected{{ end }}>8 Digit Code</option>
                        </select>
                      </div>
                    </div>
                    <p><b>Step 2</b>: Open your MFA authenticator application, e.g. Microsoft/Google Authenticator, Authy, etc.,
                      add new entry and click the "Get QR" link.
                    </p>
                    <div id="mfa-get-qr-code" class="center-align">
                      <a href="#qr-code-mode" onclick="getQRCode()">Get QR Code</a>
                    </div>
                  </div>
                  <div id="mfa-qr-code" class="hide">
                    <h6 id="qr-code-mode" class="hide">QR Code Mode</h6>
                    <div class="center-align">
                      <p>&raquo; Scan the QR code image.</p>
                    </div>
                    <div id="mfa-qr-code-image" class="center-align">
                      <img src="{{ pathjoin .ActionEndpoint "/settings/mfa/barcode/" .Data.code_uri_encoded }}.png" alt="QR Code" />
                    </div>
                    <div class="center-align">
                      <p>&raquo; Can't scan? Click or copy the link below.</p>
                    </div>
                    <div id="mfa-no-camera-link" class="center-align">
                      <a href="{{ .Data.code_uri }}">No Camera Link</a>
                    </div>
                    <p><b>Step 3</b>: Enter the authentication code you see in the app and click "Add".</p>
                    <div class="input-field mfa-app-auth-ctrl mfa-app-auth-form">
                      <input class="mfa-app-auth-passcode" id="passcode" name="passcode" type="text" class="validate" pattern="[0-9]{4,8}"
                        title="Authentication code should contain 4-8 characters and consists of 0-9 characters."
                        autocorrect="off" autocapitalize="off" autocomplete="off"
                        placeholder="______"
                        required />
                    </div>
                    <input id="email" name="email" type="hidden" value="{{ .Data.mfa_email }}" />
                    <input id="type" name="type" type="hidden" value="{{ .Data.mfa_type }}" />
                    <input id="barcode_uri" name "barcode_uri" type="hidden" value="{{ pathjoin .ActionEndpoint "/settings/mfa/barcode/"}}" />
                    <div class="row right">
                      <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                        <i class="las la-plus-circle left app-btn-icon"></i>
                        <span class="app-btn-text">Add</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "mfa-add-app-status" }}
          <div class="row">
            <div class="col s12">
            <h1>MFA Token</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            {{ if eq .Data.status "SUCCESS" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            {{ else }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa/add/app" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "mfa-test-app" }}
            <form id="mfa-test-app-form" action="{{ pathjoin .ActionEndpoint "/settings/mfa/test/app/" .Data.mfa_digits .Data.mfa_token_id }}" method="POST">
              <div class="row">
                <h1>Test MFA Authenticator Application</h1>
                <div class="row">
                  <div class="col s12 m12 l12">
                    <p>Please open your MFA authenticator application to view your authentication code and verify your identity</p>
                    <div class="input-field mfa-app-auth-ctrl mfa-app-auth-form">
                      <input class="mfa-app-auth-passcode" id="passcode" name="passcode" type="text" class="validate" pattern="[0-9]{4,8}"
                        title="Authentication code should contain 4-8 characters and consists of 0-9 characters."
                        maxlength="6"
                        autocorrect="off" autocapitalize="off" autocomplete="off"
                        placeholder="______"
                        required />
                    </div>
                    <input id="token_id" name="token_id" type="hidden" value="{{ .Data.mfa_token_id }}" />
                    <input id="digits" name="digits" type="hidden" value="{{ .Data.mfa_digits }}" />
                    <div class="center-align">
                      <button type="reset" name="reset" class="btn waves-effect waves-light navbtn active navbtn-last red lighten-1">
                        <i class="las la-redo-alt left app-btn-icon"></i>
                      </button>
                      <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last">
                        <i class="las la-check-square left app-btn-icon"></i>
                        <span class="app-btn-text">Verify</span>
                      </button>
                  </div>
                </div>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "mfa-test-app-status" }}
          <div class="row">
            <div class="col s12">
            <h1>Test MFA Authenticator Application</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            {{ if eq .Data.status "SUCCESS" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            {{ else }}
              {{ if ne .Data.mfa_token_id "" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa/test/app/" .Data.mfa_digits .Data.mfa_token_id }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
              {{ end }}
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "mfa-delete-status" }}
          <div class="row">
            <div class="col s12">
            <h1>MFA Token</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            <a href="{{ pathjoin .ActionEndpoint "/settings/mfa" }}">
              <button type="button" class="btn waves-effect waves-light navbtn active">
                <i class="las la-undo-alt left app-btn-icon"></i>
                <span class="app-btn-text">Go Back</span>
              </button>
            </a>
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "mfa-add-u2f" }}
            <form id="mfa-add-u2f-form" action="{{ pathjoin .ActionEndpoint "/settings/mfa/add/u2f" }}" method="POST">
              <div class="row">
                <div class="col s12">
                  <h1>Add U2F Security Key</h1>
                  <p>Please insert your U2F (USB, NFC, or Bluetooth) Security Key, e.g. Yubikey.</p>
                  <p>Then, please click "Register" button below.</p>
                  <div class="input-field">
                    <input id="comment" name="comment" type="text" class="validate" pattern="[A-Za-z0-9 -]{4,25}"
                      title="Authentication code should contain 4-25 characters and consists of A-Z, a-z, 0-9, space, and dash characters."
                      autocorrect="off" autocapitalize="off" autocomplete="off"
                      required />
                    <label for="comment">Comment</label>
                  </div>
                  <input class="hide" id="webauthn_register" name="webauthn_register" type="text" />
                  <input class="hide" id="webauthn_challenge" name="webauthn_challenge" type="text" value="{{ .Data.webauthn_challenge }}" />
                  <button id="mfa-add-u2f-button" type="button" name="action" onclick="u2f_token_register('mfa-add-u2f-form', 'mfa-add-u2f-button');" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                    <i class="las la-plus-circle left app-btn-icon"></i>
                    <span class="app-btn-text">Register</span>
                  </button>
                </div>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "mfa-add-u2f-status" }}
          <div class="row">
            <div class="col s12">
            <h1>U2F Security Key</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            {{ if eq .Data.status "SUCCESS" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            {{ else }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa/add/u2f" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "mfa-test-u2f" }}
            <form id="mfa-test-u2f-form" action="{{ pathjoin .ActionEndpoint "/settings/mfa/test/u2f/generic" .Data.mfa_token_id }}" method="POST">
              <div class="row">
                <div class="col s12 m12 l12">
                  <h1>Test Token</h1>
                  <p>
                    Insert your hardware token into a USB port.
                    Next, click "Authenticate" button below.
                    When prompted, touch, or otherwise trigger the hardware token.
                  </p>
                  <input id="webauthn_request" name="webauthn_request" type="hidden" />
                  <a id="mfa-test-u2f-button" onclick="u2f_token_authenticate('mfa-test-u2f-form', 'mfa-test-u2f-button');" class="btn waves-effect waves-light navbtn active navbtn-last">
                    <i class="las la-check-square left app-btn-icon"></i>
                    <span class="app-btn-text">Verify</span>
                  </a>
                </div>
                <input id="token_id" name="token_id" type="hidden" value="{{ .Data.mfa_token_id }}" />
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "mfa-test-u2f-status" }}
          <div class="row">
            <div class="col s12">
            <h1>Test Token</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            {{ if eq .Data.status "SUCCESS" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            {{ else }}
              {{ if ne .Data.mfa_token_id "" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa/test/u2f/generic" .Data.mfa_token_id }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
              {{ end }}
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "password" }}
            <form action="{{ pathjoin .ActionEndpoint "/settings/password/edit" }}" method="POST">
              <div class="row">
                <h1>Password Management</h1>
                <div class="row">
                  <div class="col s12 m6 l6">
                    <p>If you want to change your password, please provide your current password and 
                    </p>
                    <div class="input-field">
                      <input id="secret1" name="secret1" type="password" autocorrect="off" autocapitalize="off" autocomplete="off" required />
                      <label for="secret1">Current Password</label>
                    </div>
                    <div class="input-field">
                      <input id="secret2" name="secret2" type="password" autocorrect="off" autocapitalize="off" autocomplete="off" required />
                      <label for="secret2">New Password</label>
                    </div>
                    <div class="input-field">
                      <input id="secret3" name="secret3" type="password" autocorrect="off" autocapitalize="off" autocomplete="off" required />
                      <label for="secret3">Confirm New Password</label>
                    </div>
                  </div>
                </div>
              </div>
              <div class="row right">
                <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                  <i class="las la-paper-plane left app-btn-icon"></i>
                  <span class="app-btn-text">Change Password</span>
                </button>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "password-edit" }}
          <div class="row">
            <div class="col s12">
            {{ if eq .Data.status "SUCCESS" }}
              <h1>Password Has Been Changed</h1>
              <p>Please log out and log back in.</p>
            {{ else }}
              <h1>Password Change Failed</h1>
              <p>Reason: {{ .Data.status_reason }} </p>
              <a href="{{ pathjoin .ActionEndpoint "/settings/password" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "misc" }}
          <div class="row">
            <div class="col s12">
            <p>The {{ .Data.view }} view is under construction.</p>
            </div>
          </div>
          {{ end }}
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/materialize-css/js/materialize.js" }}"></script>
    {{ if or (eq .Data.view "sshkeys-add") (eq .Data.view "gpgkeys-add") (eq .Data.view "sshkeys-view") (eq .Data.view "gpgkeys-view") }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/highlight.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/languages/json.min.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/languages/plaintext.min.js" }}"></script>
    {{ end }}
    {{ if or (eq .Data.view "mfa-add-u2f") (eq .Data.view "mfa-test-u2f") }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/cbor/cbor.js" }}"></script>
    {{ end }}
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
    {{ if or (eq .Data.view "mfa-add-app") (eq .Data.view "mfa-test-app") }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/mfa_add_app.js" }}"></script>
    {{ end }}
    {{ if eq .Data.view "mfa-add-u2f" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/mfa_add_u2f.js" }}"></script>
    {{ end }}
    {{ if eq .Data.view "mfa-test-u2f" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/mfa_add_u2f.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/mfa_test_u2f.js" }}"></script>
    {{ end }}
    {{ if or (eq .Data.view "sshkeys-add") (eq .Data.view "gpgkeys-add") (eq .Data.view "sshkeys-view") (eq .Data.view "gpgkeys-view") }}
    <script>
    hljs.initHighlightingOnLoad();
    </script>
    {{ end }}
    {{ if .Message }}
    <script>
    var toastHTML = '<span class="app-error-text">{{ .Message }}</span><button class="btn-flat toast-action" onclick="M.Toast.dismissAll();">Close</button>';
    toastElement = M.toast({
      html: toastHTML,
      classes: 'toast-error'
    });
    const appContainer = document.querySelector('.app-container')
    appContainer.prepend(toastElement.el)
    </script>
    {{ end }}
    {{ if eq .Data.view "mfa-add-u2f" }}
    <script>
function u2f_token_register(formID, btnID) {
  const params = {
    challenge: "{{ .Data.webauthn_challenge }}",
    rp_name: "{{ .Data.webauthn_rp_name }}",
    user_id: "{{ .Data.webauthn_user_id }}",
    user_name: "{{ .Data.webauthn_user_email }}",
    user_display_name: "{{ .Data.webauthn_user_display_name }}",
    user_verification: "{{ .Data.webauthn_user_verification }}",
    attestation: "{{ .Data.webauthn_attestation }}",
    pubkey_cred_params: [
      {
        type: "public-key",
        alg: -7,
      },
    ]
  };
  register_u2f_token(formID, btnID, params);
}
    </script>
    {{ end }}

    {{ if eq .Data.view "mfa-test-u2f" }}
    <script>
function u2f_token_authenticate(formID, btnID) {
  const params = {
    challenge: "{{ .Data.webauthn_challenge }}",
    timeout: {{ .Data.webauthn_timeout }},
    rp_name: "{{ .Data.webauthn_rp_name }}",
    user_verification: "{{ .Data.webauthn_user_verification }}",
    {{ if .Data.webauthn_credentials }}
    allowed_credentials: [
    {{ range .Data.webauthn_credentials }}
      {
        id: "{{ .id }}",
        type: "{{ .type }}",
        transports: [{{ .transports }}],
      },
    {{ end }}
    ],
    {{ else }}
    allowed_credentials: [],
    {{ end }}
    ext_uvm: {{ .Data.webauthn_ext_uvm }},
    ext_loc: {{ .Data.webauthn_ext_loc }},
    ext_tx_auth_simple: "{{ .Data.webauthn_tx_auth_simple }}",
  };
  authenticate_u2f_token(formID, btnID, params);
}
    </script>
    {{ end }}
  </body>
</html>`,
	"basic/sandbox": `<!doctype html>
<html lang="en">
  <head>
    <title>{{ .Title }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Authentication Portal">
    <meta name="author" content="Paul Greenberg github.com/greenpau">
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">
    <!-- Matrialize CSS -->
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/materialize-css/css/materialize.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/montserrat.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/styles.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
    {{ if or (eq .Data.view "mfa_app_auth") (eq .Data.view "mfa_app_register") }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/mfa_app.css" }}" />
    {{ end }}
  </head>
  <body class="app-body">
    <div class="container">
      <div class="row">
        <div class="col s12 m8 offset-m2 l4 offset-l4 app-card-container">
          <div class="row app-header center">
            {{ if .LogoURL }}
            <div class"row center">
              <a href="{{ pathjoin .ActionEndpoint }}">
                <img class="d-block mx-auto mb-2" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" width="72" height="72">
              </a>
            </div>
            {{ end }}
            <div class"row center">
              <h5>{{ .Title }}</h5>
            </div>
          </div>
          {{ if or (eq .Data.view "mfa_mixed_auth") (eq .Data.view "mfa_mixed_register") }}
          <div class="row center">
            <p>
              Your session requires multi-factor authentication.
              {{ if eq .Data.view "mfa_mixed_register" }}
              However, you do not have second factor authentication method configured.
              Please click the authentication methods below to proceed with the configuration.
              {{ else }}
              Please click the appropriate second factor authentication method to proceed further.
              {{ end }}
            </p>
          </div>
          <div class="row">
            <ul class="collection">
              <li class="collection-item">
                <i class="las la-mobile la-lg"></i>
                <a href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-app-auth" }}">Authenticator App</a>
              </li>
              <li class="collection-item">
                <i class="las la-microchip la-lg"></i>
                <a href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-u2f-auth" }}">Hardware Token</a>
              </li>
            </ul>
          </div>
          {{ else if eq .Data.view "mfa_app_auth" }}
          <div class="row">
            <form class="mfa-app-auth-form"
                  action="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-app-auth" }}"
                  method="POST"
                  autocomplete="off"
                  >
              <div class="mfa-app-auth-ctrl">
                <input class="mfa-app-auth-passcode" id="passcode" name="passcode" type="text" class="validate" pattern="[0-9]{4,8}"
                       title="Passcode should contain 4, 6, or 8 characters and consists of 0-9 characters."
                       maxlength="8"
                       placeholder="______"
                       autocorrect="off" autocapitalize="off" autocomplete="off"
                       required />
              </div>
              <input id="sandbox_id" name="sandbox_id" type="hidden" value="{{ .Data.id }}" />
              <div class="mfa-app-auth-btn">
                <button type="reset" name="reset" class="btn waves-effect waves-light navbtn active navbtn-last red lighten-1">
                  <i class="las la-redo-alt left app-btn-icon"></i>
                </button>
                <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last">
                  <i class="las la-check-square left app-btn-icon"></i>
                  <span class="app-btn-text">Verify</span>
                </button>
              </div>
            </form>
            <div class="mfa-auth-help-text">
              <p>
                Open the two-factor authentication app on your device to view your
                authentication code and verify your identity.
              </p>
            </div>
            <div class="mfa-auth-help-menu">
              <p>Having issues?</p>
              <ul>
                <li>
                  <i class="las la-lock-open"></i>
                  <a href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-app-recovery" }}">
                    Enter a two-factor recovery code
                  </a>
                </li>
                <li>
                  <i class="las la-question"></i>
                  <a href="{{ pathjoin .ActionEndpoint "help" }}">
                    Contact support
                  </a>
                </li>
              </ul>
            </div>
          </div>
          {{ else if eq .Data.view "mfa_u2f_auth" }}
          <div class="row">
            <form class="mfa-u2f-auth-form"
                  action="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-u2f-auth" }}"
                  method="POST"
                  autocomplete="off"
                  >
              <input id="u2f_auth_request" name="u2f_auth_request" type="hidden" value="" />
              <input id="sandbox_id" name="sandbox_id" type="hidden" value="{{ .Data.id }}" />
            </form>
            <div class="mfa-auth-help-text">
              <p>
                Insert your hardware token into a USB port. When prompted, touch,
                or otherwise trigger the hardware token.
              </p>
            </div>
            <div class="mfa-auth-help-menu">
              <p>Having issues?</p>
              <ul>
                <li>
                  <i class="las la-question"></i>
                  <a href="{{ pathjoin .ActionEndpoint "help" }}">
                    Contact support
                  </a>
                </li>
              </ul>
            </div>
          </div>
          {{ else if eq .Data.view "mfa_app_register" }}
          <div class="row">
            <p>The {{ .Data.view }} view is under construction.</p>
          </div>
          {{ else if eq .Data.view "mfa_u2f_register" }}
          <div class="row">
            <p>The {{ .Data.view }} view is under construction.</p>
          </div>
          {{ else if eq .Data.view "error" }}
          <div class="row center">
            <p>Your session failed to meet authorization requirements.</p>
            <p>{{ .Data.error }}.</p>
            <a href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id }}">
              <button type="button" name="button" class="btn waves-effect waves-light navbtn active navbtn-last red lighten-1">
                <i class="las la-redo-alt left app-btn-icon"></i>
                <span class="app-btn-text">Try Again</span>
              </button>
            </a>
          </div>
          {{ else }}
          <div class="row">
            <p>The {{ .Data.view }} view is unsupported.</p>
          </div>
          {{ end }}
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/materialize-css/js/materialize.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
    {{ if .Message }}
    <script>
    var toastHTML = '<span>{{ .Message }}</span><button class="btn-flat toast-action" onclick="M.Toast.dismissAll();">Close</button>';
    toastElement = M.toast({
      html: toastHTML,
      classes: 'toast-error'
    });
    const appContainer = document.querySelector('.app-card-container')
    appContainer.prepend(toastElement.el)
    </script>
    {{ end }}
  </body>
</html>`,
}
