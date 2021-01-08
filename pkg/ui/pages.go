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
          <form action="{{ .ActionEndpoint }}" method="POST">
            <div class="row app-form">
              {{ if eq .Data.login_options.username_required "yes" }}
              <div class="row app-input-row valign-wrapper">
                <div class="col s4">
                  <p class="app-input-text">Username</p>
                </div>
                <div class="col s8">
                  <div class="input-field app-input-field">
                    <input id="username" name="username" type="text" class="validate">
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
                    <input id="password" name="password" type="password" class="validate">
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
        <div class="col s12 m12 l6 offset-l3">
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
                  pattern="[a-z0-9]{3,25}"
                  title="Username should contain maximum of 25 characters and consists of a-z and 0-9 characters."
                  required />
                <label for="username">Username</label>
              </div>
              <div class="input-field">
                <input id="email" name="email" type="email" class="validate"
                  required />
                <label for="email">Email Address</label>
              </div>
              <div class="input-field">
                <input id="password" name="password" type="password" class="validate" required />
                <label for="password">Password</label>
              </div>
              <div class="input-field">
                <input id="password_confirm" name="password_confirm" type="password" class="validate" required />
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
                    <a href="{{ pathjoin .ActionEndpoint "/termsandconditions" }}">Terms and Conditions</a> and
                    <a href="{{ pathjoin .ActionEndpoint "/privacypolicy" }}">Privacy Policy</a>.
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
      classes: 'toast-error'
    });
    const appContainer = document.querySelector('.app-card-container')
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
                  <img class="d-block mx-auto mb-2" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" width="72" height="72">
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
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/highlight.js/css/atom-one-dark.min.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/styles.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
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
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/sshkeys/delete/" .ID }}">Delete</a>
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/sshkeys/get/" .ID }}">View</a>
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
                    <input placeholder="Comment" name="comment1" id="comment1" type="text" class="validate">
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
              <p>List of registered GPG Keys</p>
              {{range .Data.gpgkeys}}
              <p>
                ID: {{ .ID }}<br/>
              </p>
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
                    <input placeholder="Comment" name="comment1" id="comment1" type="text" class="validate">
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
                    <b>Type</b>: {{ .Type }}<br/>
                    <b>Algorithm</b>: {{ .Algorithm }}<br/>
                    <b>Period</b>: {{ .Period }} seconds<br/>
                    <b>Digits</b>: {{ .Digits }}<br/>
                    <b>Created At</b>: {{ .CreatedAt }}
                  </p>
                </div>
                <div class="card-action">
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/mfa/delete/" .ID }}">Delete</a>
                  {{ if eq .Type "totp" }}
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/mfa/test/app/" .ID }}">Test</a>
                  {{ end }}
                  {{ if eq .Type "u2f" }}
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/mfa/test/u2f/" .ID }}">Test</a>
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
            <form action="{{ pathjoin .ActionEndpoint "/settings/mfa/add/app" }}" method="POST">
              <div class="row">
                <h1>Add MFA Authenticator Application</h1>
                <div class="row">
                  <div class="col s12 m6 l6">
                    <p>Please add your MFA authenticator application, e.g. Microsoft/Google Authenticator, Authy, etc.</p>
                    <p>If your MFA application supports scanning QR codes, scan the QR code image.</p>
                    <p>After adding this account to the MFA authenticator application, enter two consecutive authentication codes in the boxes below and click "Add".</p>
                    <div class="input-field">
                      <input id="comment" name="comment" type="text" class="validate" pattern="[A-Za-z0-9 -]{4,25}"
                        title="Authentication code should contain 4-25 characters and consists of A-Z, a-z, 0-9, space, and dash characters."
                        required />
                      <label for="comment">Comment</label>
                    </div>
                    <div class="input-field">
                      <input id="code1" name="code1" type="text" class="validate" pattern="[0-9]{6}"
                        title="Authentication code should contain 6 characters and consists of 0-9 characters."
                        required />
                      <label for="code1">Authentication Code 1</label>
                    </div>
                    <div class="input-field">
                      <input id="code2" name="code2" type="text" class="validate" pattern="[0-9]{6}"
                        title="Authentication code should contain 6 characters and consists of 0-9 characters."
                        required />
                      <label for="code2">Authentication Code 2</label>
                    </div>
                    <input id="secret" name="secret" type="hidden" value="{{ .Data.mfa_secret }}" />
                    <input id="type" name="type" type="hidden" value="{{ .Data.mfa_type }}" />
                    <input id="period" name="period" type="hidden" value="{{ .Data.mfa_period }}" />
                    <input id="digits" name="digits" type="hidden" value="{{ .Data.mfa_digits }}" />
                  </div>
                  <div class="col s12 m6 l6">
                    <div class="center-align"><img src="{{ pathjoin .ActionEndpoint "/settings/mfa/barcode/" .Data.code_uri_encoded }}.png" alt="QR Code" /></div>
                    <div class="center-align"><a href="{{ .Data.code_uri }}">Link</a></div>
                  </div>
                </div>
              </div>
              <div class="row right">
                <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                  <i class="las la-plus-circle left app-btn-icon"></i>
                  <span class="app-btn-text">Add Token</span>
                </button>
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
            <form action="{{ pathjoin .ActionEndpoint "/settings/mfa/test/app/" .Data.mfa_token_id }}" method="POST">
              <div class="row">
                <h1>Test MFA Authenticator Application</h1>
                <div class="row">
                  <div class="col s12 m6 l6">
                    <p>Please open your MFA authenticator application to view your authentication code and verify your identity</p>
                    <div class="input-field">
                      <input id="passcode" name="passcode" type="text" class="validate" pattern="[0-9]{6}"
                        title="Passcode should contain 6 characters and consists of 0-9 characters."
                        required />
                      <label for="passcode">Passcode</label>
                    </div>
                    <input id="token_id" name="token_id" type="hidden" value="{{ .Data.mfa_token_id }}" />
                  </div>
                </div>
              </div>
              <div class="row">
                <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                  <i class="las la-plus-circle left app-btn-icon"></i>
                  <span class="app-btn-text">Validate</span>
                </button>
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
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa/test/app/" .Data.mfa_token_id }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
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
                      required />
                    <label for="comment">Comment</label>
                  </div>
                  <input class="hide" id="webauthn_register" name="webauthn_register" type="text" />
                  <input class="hide" id="webauthn_challenge" name="webauthn_challenge" type="text" value="{{ .Data.webauthn_challenge }}" />
                  <button id="mfa-add-u2f-button" type="button" name="action" onclick="register_u2f_token()" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
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
          {{ if eq .Data.view "password" }}
            <form action="{{ pathjoin .ActionEndpoint "/settings/password/edit" }}" method="POST">
              <div class="row">
                <h1>Password Management</h1>
                <div class="row">
                  <div class="col s12 m6 l6">
                    <p>If you want to change your password, please provide your current password and 
                    </p>
                    <div class="input-field">
                      <input id="secret1" name="secret1" type="password" required />
                      <label for="secret1">Current Password</label>
                    </div>
                    <div class="input-field">
                      <input id="secret2" name="secret2" type="password" required />
                      <label for="secret2">New Password</label>
                    </div>
                    <div class="input-field">
                      <input id="secret3" name="secret3" type="password" required />
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
            {{ if eq .Data.status "success" }}
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
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/highlight.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/languages/json.min.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/cbor/cbor.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
    <script>
    hljs.initHighlightingOnLoad();
    </script>
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
    function str_to_uint8_array(s) {
      buf = [];
      for (var i = 0; i < s.length; i+=2) {
        var j = parseInt(s.substring(i, i + 2), 16);
        buf.push(j);
      }
      return Uint8Array.from(buf);
    }

    function uint8array_to_buffer(arr) {
			return arr.buffer.slice(arr.byteOffset, arr.byteLength + arr.byteOffset)
		}

    function buffer_to_hex(buffer) {
			return uint8array_to_hex(new Uint8Array(buffer));
		}

		function uint8array_to_hex(arr) {
			return Array.prototype.map.call(arr, function (x) {
				return ('00' + x.toString(16)).slice(-2);
			}).join('');
		}

    function buffer_to_base64(buffer) {
			return uint8array_to_base64(new Uint8Array(buffer));
		}

    function uint8array_to_base64(array) {
			return window.btoa(String.fromCharCode.apply(null, array));
		}

    function parseAttestationObjectAttestationStatement(attStmt) {
      // See Packed Attestation Statement Format for details
      // https://www.w3.org/TR/webauthn-1/#packed-attestation
      console.log("attStmt");
      console.log(attStmt);
      response = {
        // Algorithms, see IANA COSE Algorithms registry
        // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        // -7: ES256 (ECDSA w/ SHA-256)
        // -257: RS256 (RSASSA-PKCS1-v1_5 using SHA-256)
        "alg": attStmt.alg
			}

      if (!('sig' in attStmt)) {
        throw "sig not found in attestation statement";
      }
      // A byte string containing the attestation signature
      response["sig"] = uint8array_to_base64(attStmt.sig);

      if ('x5c' in attStmt) {
				// Handle non-ECDAA attestation type
        var certChain = [];
        // The elements of this array contain attestnCert and its
        // certificate chain, each encoded in X.509 format. The attestation
        // certificate attestnCert MUST be the first element in the array.
        response["x5c"] = []
        attStmt.x5c.forEach(item => response.x5c.push(uint8array_to_base64(item)));
      } else {
				if ('ecdaaKeyId' in attStmt) {
					// Handle ECDAA attestation type
				} else {
          throw "ecdaaKeyId not found in attestation statement";
				}
      }

      return response
    }

    function parseAttestationObjectAuthData(data) {
      // See https://www.w3.org/TR/webauthn-1/#sctn-attestation
      var dv = new DataView(data, 0);
      console.log(dv.byteLength);
      var offset = 0;
      var rp_id_hash  = dv.buffer.slice(offset, offset + 32); offset += 32;
      var flags = dv.getUint8(offset); offset += 1;
      var counter = dv.getUint32(offset, false); offset += 4;
      var response = {
        'rpIdHash': buffer_to_hex(rp_id_hash),
        'flags': {
					'UP':    !!(flags & 0x01), // User Present (UP)
					'RFU1':  !!(flags & 0x02),
					'UV':    !!(flags & 0x04), // User Verified (UV)
					'RFU2a': !!(flags & 0x08),
					'RFU2b': !!(flags & 0x10),
					'RFU2c': !!(flags & 0x20),
					'AT':    !!(flags & 0x40), // Attested credential data included
					'ED':    !!(flags & 0x80)  // Extension data included
				},
				'signatureCounter': counter,
        'credentialData': {},
        'extensions': {}
			};

      console.log("response");
      console.log(response);
      console.log(offset);


      if (response['flags']['AT']) {
        var aaguid = dv.buffer.slice(offset, offset + 16); offset += 16;
        console.log("aaguid");
        console.log(aaguid);
        console.log(buffer_to_base64(aaguid));
        response['credentialData']['aaguid'] = buffer_to_base64(aaguid);
        var credentialIdLength = dv.getUint16(offset); offset += 2;
        console.log("credentialIdLength");
        console.log(credentialIdLength);
        var credentialId = dv.buffer.slice(offset, credentialIdLength); offset += credentialIdLength;
        response['credentialData']['credentialId'] = buffer_to_base64(credentialId)
        console.log("credentialId");
        console.log(response['credentialData']['credentialId']);
        var publicKeyBytes = dv.buffer.slice(offset);
        console.log("publicKeyBytes");
        console.log(publicKeyBytes);
        var publicKeyObject = CBOR.decode(publicKeyBytes);
        console.log("publicKeyObject");
        console.log(publicKeyObject);


        // TODO: fix it! The is no length!!
        console.log(typeof publicKeyBytes);
        // console.log(len(publicKeyBytes));

        offset += publicKeyObject['length'];

        // TODO: PEM object
        console.log("CBOR decoded");
        response['credentialData']['publicKey'] = {
          // See COSE Key Types: https://www.iana.org/assignments/cose/cose.xhtml#key-type
          // 2 = Elliptic Curve Keys w/ x- and y-coordinate pair
          'key_type': publicKeyObject[1],
          // See COSE Algorithms: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
          // -7 = ECDSA with SHA256
					'algorithm': publicKeyObject[3],
          // See COSE Elliptic Curves: https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
          // 1 = P-256 (NIST P-256 also known as secp256r1)
  				'curve_type': publicKeyObject[-1],
          // Elliptic Curve x-coordinate as byte string 32 bytes in length
	  			'curve_x': uint8array_to_base64(publicKeyObject[-2]),
          // Elliptic Curve y-coordinate as byte string 32 bytes in length
					'curve_y': uint8array_to_base64(publicKeyObject[-3]),
        }
      }

      if (response['flags']['ED']) {
        // var extensionData = dv.buffer.slice(offset);
      }

      console.log(response);
      return response;
    }

    function parseNavigatorCredentialsCreateResponse(result) {
      var decoder = new TextDecoder('utf-8');
      clientData = JSON.parse(decoder.decode(result.response.clientDataJSON));
      console.log("clientData");
      console.log(clientData);
      console.log("result");
      console.log(result);
      var attestationObject = CBOR.decode(result.response.attestationObject);
      var attestationObjectAuthData = uint8array_to_buffer(attestationObject.authData);
      console.log("attestationObject");
      console.log(attestationObject);
      console.log("attestationObjectAuthData");
      console.log(attestationObjectAuthData);
      var authData = parseAttestationObjectAuthData(attestationObjectAuthData);
      var attStmt = parseAttestationObjectAttestationStatement(attestationObject.attStmt);

      var response = {
        "success": true,
        "attestationObject": {
          "attStmt": attStmt,
          "authData": authData,
          "fmt": attestationObject.fmt
        },
        "clientData": clientData,
        "device": {
          "name": "Unknown device",
          "type": "unknown"
        }
      }
      return response;
    }

    function register_u2f_token() {
      var btn = document.getElementById("mfa-add-u2f-button");
      btn.classList.add("hide");
      var publicKeyOptions = {
        "challenge": str_to_uint8_array("{{ .Data.webauthn_challenge }}"),
        "rp": {
          "name": "{{ .Data.webauthn_rp_name }}"
        },
        "user": {
          "id": str_to_uint8_array("{{ .Data.webauthn_user_id }}"),
          "name": "{{ .Data.webauthn_user_email }}",
          "displayName": "{{ .Data.webauthn_user_display_name }}"
        },
        authenticatorSelection: {
          userVerification: "discouraged"
        },
        attestation: "direct",
        pubKeyCredParams: [
          {
            type: "public-key",
            alg: -7
          }
        ]
      };
      console.log("public key options");
      console.log(publicKeyOptions);
      if ('credentials' in navigator) {
        navigator.credentials
        .create({publicKey: publicKeyOptions})
        .then(result => {
          response = parseNavigatorCredentialsCreateResponse(result);
          console.log('navigator.credentials.create() response');
          console.log(response);
          jresponse = btoa(JSON.stringify(response));
          console.log(jresponse);
          document.getElementById("webauthn_register").value = jresponse;
          document.getElementById("mfa-add-u2f-form").submit();
        })
        .catch(err => {
          console.log(err);
          err_msg = err.name + ': ' + err.message;
          console.log(err_msg)
        });
      } else {
        // TODO: 'navigator.credentials is not supported'
        console.log('navigator.credentials is not supported')
      }
    }
    </script>
    {{ end }}
  </body>
</html>`,
}
