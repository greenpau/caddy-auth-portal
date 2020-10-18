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
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css" integrity="sha256-OweaP/Ic6rsV+lysfyS4h+LM6sRwuO3euTYfr6M124g=" crossorigin="anonymous" />
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css" integrity="sha384-wvfXpqpZZVQGK6TAh5PVlGOfQNHSoD2xbE+QkPxCAFlNEevoEH3Sl0sibVcOQVnN" crossorigin="anonymous">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@500&display=swap" rel="stylesheet">
    <style>
      input {
        font-family: 'Roboto', sans-serif;
      }
      .app-background {
        background-color: #155D56;
      }
      .app-card-container {
        background-color: white;
        box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2);
        transition: 0.3s;
        margin-top: 2em;
        padding-top: 1em !important;
        padding-left: 2em !important;
        padding-right: 2em !important;

      }
      .app-header {
        font-family: 'Roboto', sans-serif;
        padding-top: 1em !important;
        color: #EE6E73;
        font-size: 1.25rem;
      }
      .app-form, .app-control {
        font-family: 'Roboto', sans-serif;
        font-size: 1.25rem;
      }
      .app-link a:link, .app-link a:visited, .app-link a:active, .app-link a:hover {
        font-size: 1rem;
        text-transform: none !important;
        display: block;
      }
      .app-link a:link, .app-link a:visited, .app-link a:active {
        color: #EE6E73 !important;
      }
      .app-link a:hover {
        color: #F3999D !important;
      }
      .app-input-row {
        line-height: 2px !important;
        font-family: 'Roboto', sans-serif;
        font-size: 1rem;
        margin-bottom: 1px;
      }
      p.app-input-text {
        color: #52504f;
      }
      .app-input-field {
        color: #52504f;
        margin-bottom: 0px;
        margin-top: 0.25rem;
      }
      p.app-text {
        font-family: 'Roboto', sans-serif;
        color: #52504f;
        padding-top: 1em !important;
      }
      span.app-icon-text {
        font-family: 'Roboto', sans-serif;
        padding-left: 0.5rem;
      }
      span.app-error-text {
        font-family: 'Roboto', sans-serif;
      }
      .app-icon-btn {
        margin-bottom: 1rem;
      }
      .toast-error {
        // restyle post
      }
      .helper-btn {
        margin-bottom: 0.15em;
      }
      input:-webkit-autofill,
      input:-webkit-autofill:hover, 
      input:-webkit-autofill:focus, 
      input:-webkit-autofill:active  {
          -webkit-box-shadow: 0 0 0 30px white inset !important;
      }
    </style>
  </head>
  <body class="app-background">
    <div class="container app-container">
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
                <button type="submit" name="submit" class="btn waves-effect waves-light">
                  <span class="app-icon-text">Login</span>
                  <i class="material-icons left">send</i>
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
            <a class="app-icon-btn btn waves-effect waves-light {{ .color }}" href="{{ .endpoint }}">
              <i class="fa fa-{{ .icon }}"></i><span class="app-icon-text">{{ .text }}</span>
            </a>
            {{ end }}
          </div>
          {{ end }}
        </div>
      </div>
    </div>
    <!-- Optional JavaScript -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js" integrity="sha256-U/cHDMTIHCeMcvehBv1xQ052bPSbJtbuiw4QA9cTKz0=" crossorigin="anonymous"></script>
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
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css" integrity="sha256-OweaP/Ic6rsV+lysfyS4h+LM6sRwuO3euTYfr6M124g=" crossorigin="anonymous" />
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.18.1/styles/atom-one-dark.min.css" integrity="sha256-GA29iW/iYj9FcuQQktvW45pRzHvZeFfgeFvA4tGVjpM=" crossorigin="anonymous" />
    <style>
      body {
        font-family: 'Roboto', sans-serif;
        font-size: 1.25rem;
      }
      input {
        font-family: 'Roboto', sans-serif;
      }
      .app-background {
        background-color: #155D56;
      }
      .app-card-container {
        background-color: white;
        box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2);
        transition: 0.3s;
        margin-top: 2em;
        padding-top: 1em !important;
        padding-left: 2em !important;
        padding-right: 2em !important;
      }
      .app-header {
        font-family: 'Roboto', sans-serif;
        padding-top: 1em !important;
        color: #EE6E73;
        font-size: 1.25rem;
      }
      .app-header {
        color: #EE6E73;
      }
      .toast-error {
        // restyle post
      }
      .navbtn {
        font-family: 'Roboto', sans-serif;
      }
      .navbtn-last {
        margin-right: 0px !important;
      }
      input:-webkit-autofill,
      input:-webkit-autofill:hover, 
      input:-webkit-autofill:focus, 
      input:-webkit-autofill:active  {
          -webkit-box-shadow: 0 0 0 30px white inset !important;
      }
    </style>
  </head>
  <body class="app-background">
    <div class="container app-container">
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
            <p>Access the following services.</p>
            <ul class="collection">
              {{range .PrivateLinks}}
              <li class="collection-item">
                <a href="{{ .Link }}">{{ .Title }}</a>
              </li>
              {{ end }}
            </ul>
          </div>
          <div class="row right">
            <a href="{{ pathjoin .ActionEndpoint "/logout" }}" class="navbtn-last">
              <button type="button" class="btn waves-effect waves-light navbtn active navbtn-last">
                <span class="white-text"><i class="material-icons left">power_settings_new</i>Logout</span>
              </button>
            </a>
          </div>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js" integrity="sha256-U/cHDMTIHCeMcvehBv1xQ052bPSbJtbuiw4QA9cTKz0=" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.18.1/highlight.min.js" integrity="sha256-eOgo0OtLL4cdq7RdwRUiGKLX9XsIJ7nGhWEKbohmVAQ=" crossorigin="anonymous"></script>
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
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css" integrity="sha256-OweaP/Ic6rsV+lysfyS4h+LM6sRwuO3euTYfr6M124g=" crossorigin="anonymous" />
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.18.1/styles/atom-one-dark.min.css" integrity="sha256-GA29iW/iYj9FcuQQktvW45pRzHvZeFfgeFvA4tGVjpM=" crossorigin="anonymous" />
    <style>
      body {
        font-family: 'Roboto', sans-serif;
        font-size: 1.25rem;
      }
      input {
        font-family: 'Roboto', sans-serif;
      }
      .app-background {
        background-color: #155D56;
      }
      .app-card-container {
        background-color: white;
        box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2);
        transition: 0.3s;
        margin-top: 2em;
        padding-top: 1em !important;
        padding-left: 2em !important;
        padding-right: 2em !important;
      }
      .app-header {
        font-family: 'Roboto', sans-serif;
        padding-top: 1em !important;
        color: #EE6E73;
        font-size: 1.25rem;
      }
      .navbtn {
        font-family: 'Roboto', sans-serif;
      }
      .navbtn-last {
        margin-right: 0px !important;
      }
      .hljs {
        font-size: 1rem;
      }
      input:-webkit-autofill,
      input:-webkit-autofill:hover, 
      input:-webkit-autofill:focus, 
      input:-webkit-autofill:active  {
          -webkit-box-shadow: 0 0 0 30px white inset !important;
      }
    </style>
  </head>
  <body class="app-background">
    <div class="container app-container">
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
	          <pre><code class="json hljs">{{ .Data.token }}</code></pre>
          </div>
          <div class="row right">
            <a href="{{ pathjoin .ActionEndpoint "/portal" }}">
              <button type="button" class="btn waves-effect waves-light navbtn active">
                <span class="white-text"><i class="material-icons left">home</i>Portal</span>
              </button>
            </a>
            <a href="{{ pathjoin .ActionEndpoint "/logout" }}" class="navbtn-last">
              <button type="button" class="btn waves-effect waves-light navbtn active navbtn-last">
                <span class="white-text"><i class="material-icons left">power_settings_new</i>Logout</span>
              </button>
            </a>
          </div>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js" integrity="sha256-U/cHDMTIHCeMcvehBv1xQ052bPSbJtbuiw4QA9cTKz0=" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.18.1/highlight.min.js" integrity="sha256-eOgo0OtLL4cdq7RdwRUiGKLX9XsIJ7nGhWEKbohmVAQ=" crossorigin="anonymous"></script>
    {{ if .Message }}
    <script>
    hljs.initHighlightingOnLoad();
    </script>
    {{ end }}
  </body>
</html>`,
	"basic/register": `<!doctype html>
<html lang="en">
  <head>
    <title>{{ .Title }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css" integrity="sha256-OweaP/Ic6rsV+lysfyS4h+LM6sRwuO3euTYfr6M124g=" crossorigin="anonymous" />
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@500&display=swap" rel="stylesheet">
    <style>
      body {
        font-family: 'Roboto', sans-serif;
        font-size: 1.25rem;
      }
      input {
        font-family: 'Roboto', sans-serif;
      }
      .app-background {
        background-color: #155D56;
      }
      .app-header {
        color: #EE6E73;
      }
      .app-header img {
        float: left;
        margin-left: 5%;
      }
      p.app-body {
        color: #52504f;
        padding-top: 1em;
      }
      ol.app-body {
        color: #52504f;
        padding-right: 1em;
      }
      .navbtn {
        font-family: 'Roboto', sans-serif;
      }
      .navbtn-last {
        margin-right: 0px !important;
      }
      input:-webkit-autofill,
      input:-webkit-autofill:hover, 
      input:-webkit-autofill:focus, 
      input:-webkit-autofill:active  {
          -webkit-box-shadow: 0 0 0 30px white inset !important;
      }
    </style>
  </head>
  <body class="app-background">
    <div class="container hide-on-med-and-up no-padding" style="height: 5vh !important;"></div>
    <div class="container hide-on-small-only no-padding" style="height: 10vh !important;"></div>
    <div class="container app-container">
      <div class="row">
        <div class="col s12 m12 l6 offset-l3 app-card-container">
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
              <p class="app-body">Thank you for registering and we hope you enjoy the experience!</p>
              <p class="app-body">Here are a few things to keep in mind:</p>
              <ol class="app-body">
                <li>You should receive your confirmation email within the next 15 minutes.</li>
                <li>If you still don't see it, please email support so we can resend it to you.</li>
              </ol>
              {{ end }}
            </div>
            <div class="card-action right-align">
              {{ if not .Data.registered }}
              <button type="submit" name="submit" class="btn waves-effect waves-light btn-large">Sign Up
                <i class="material-icons left">send</i>
              </button>
              {{ else }}
              <a href="{{ .ActionEndpoint }}" class="navbtn-last">
                <button type="button" class="btn waves-effect waves-light navbtn active navbtn-last">
                  <span class="white-text"><i class="material-icons left">home</i>Portal</span>
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
    <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js" integrity="sha256-U/cHDMTIHCeMcvehBv1xQ052bPSbJtbuiw4QA9cTKz0=" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.18.1/highlight.min.js" integrity="sha256-eOgo0OtLL4cdq7RdwRUiGKLX9XsIJ7nGhWEKbohmVAQ=" crossorigin="anonymous"></script>
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
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css" integrity="sha256-OweaP/Ic6rsV+lysfyS4h+LM6sRwuO3euTYfr6M124g=" crossorigin="anonymous" />
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.18.1/styles/atom-one-dark.min.css" integrity="sha256-GA29iW/iYj9FcuQQktvW45pRzHvZeFfgeFvA4tGVjpM=" crossorigin="anonymous" />
    <style>
      body {
        font-family: 'Roboto', sans-serif;
        font-size: 1.25rem;
      }
      input {
        font-family: 'Roboto', sans-serif;
      }
      .app-background {
        background-color: #155D56;
      }
      .app-header {
        color: #EE6E73;
      }
      .navbtn {
        font-family: 'Roboto', sans-serif;
      }
      .navbtn-last {
        margin-right: 0px !important;
      }
      .hljs {
        font-size: 1rem;
      }
      input:-webkit-autofill,
      input:-webkit-autofill:hover, 
      input:-webkit-autofill:focus, 
      input:-webkit-autofill:active  {
          -webkit-box-shadow: 0 0 0 30px white inset !important;
      }
    </style>
  </head>
  <body class="app-background">
    <div class="container hide-on-med-and-up no-padding" style="height: 5vh !important;"></div>
    <div class="container hide-on-small-only no-padding" style="height: 10vh !important;"></div>
    <div class="container app-container">
      <div class="row">
        <div class="col s12 m12 l6 offset-l3 app-card-container">
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
                <button type="button" class="btn waves-effect waves-light navbtn active navbtn-last">
                  <span class="white-text"><i class="material-icons left">keyboard_return</i>Go Back</span>
                </button>
              </a>
	      {{ end }}
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js" integrity="sha256-U/cHDMTIHCeMcvehBv1xQ052bPSbJtbuiw4QA9cTKz0=" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.18.1/highlight.min.js" integrity="sha256-eOgo0OtLL4cdq7RdwRUiGKLX9XsIJ7nGhWEKbohmVAQ=" crossorigin="anonymous"></script>
    {{ if .Message }}
    <script>
    hljs.initHighlightingOnLoad();
    </script>
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
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css" integrity="sha256-OweaP/Ic6rsV+lysfyS4h+LM6sRwuO3euTYfr6M124g=" crossorigin="anonymous" />
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.18.1/styles/atom-one-dark.min.css" integrity="sha256-GA29iW/iYj9FcuQQktvW45pRzHvZeFfgeFvA4tGVjpM=" crossorigin="anonymous" />
    <style>
      body {
        font-family: 'Roboto', sans-serif;
        font-size: 1.25rem;
      }
      input {
        font-family: 'Roboto', sans-serif;
      }
      .app-container {
        background-color: white;
        box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2);
        transition: 0.3s;
        margin-top: 2em;
      }
      .app-content {
        padding-left: 1.5em !important;
        padding-right: 1.5em !important;
      }
      .app-content h1 {
        font-size: 2rem;
        color: #52504f;
        margin-top: 0.2em !important;
        margin-bottom: 0.2em !important;
      }
      .app-content p {
        color: #52504f;
      }
      .app-background {
        background-color: #155D56;
      }
      .nav-wrapper img {
        height: 100%;
        object-fit: contain;
        padding: 0.5rem 0.5rem 0.5rem 1rem;
      }
      .brand-logo {
        padding-left: 1rem !important;
      }
      .navbtn {
        font-family: 'Roboto', sans-serif;
      }
      .navbtn-last {
        margin-right: 0px !important;
      }
      .material-icons.navbar {
	font-size: 1.25rem;
	margin-top: -0.75em !important;
      }
      .hljs {
        font-size: 1rem;
      }
      input:-webkit-autofill,
      input:-webkit-autofill:hover, 
      input:-webkit-autofill:focus, 
      input:-webkit-autofill:active  {
          -webkit-box-shadow: 0 0 0 30px white inset !important;
      }
    </style>
  </head>
  <body class="app-background">
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
                    <span class="white-text"><i class="material-icons navbar left">home</i>Portal</span>
                  </button>
                </a>
              </li>
              <li>
                <a href="{{ pathjoin .ActionEndpoint "/logout" }}" class="navbtn-last">
                  <button type="button" class="btn waves-effect waves-light navbtn active navbtn-last">
                    <i class="material-icons navbar left">power_settings_new</i>Logout</button>
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
            <a href="{{ pathjoin .ActionEndpoint "/settings/passwords" }}" class="collection-item{{ if eq .Data.view "passwords" }} active{{ end }}">Passwords</a>
            <a href="{{ pathjoin .ActionEndpoint "/settings/misc" }}" class="collection-item{{ if eq .Data.view "misc" }} active{{ end }}">Miscellaneous</a>
          </div>
        </div>
        <div class="col s12 l9 app-content">
          {{ if eq .Data.view "general" }}
            <p>The {{ .Data.view }} view is under construction.</p>
          {{ end }}
          {{ if eq .Data.view "sshkeys" }}
            <p>The {{ .Data.view }} view is under construction.</p>
          {{ end }}
          {{ if eq .Data.view "gpgkeys" }}
            <p>The {{ .Data.view }} view is under construction.</p>
          {{ end }}
          {{ if eq .Data.view "apikeys" }}
            <p>The {{ .Data.view }} view is under construction.</p>
          {{ end }}
          {{ if eq .Data.view "mfa" }}
          <div class="row">
            <div class="col right">
              <a class="waves-effect waves-light btn modal-trigger" href="{{ pathjoin .ActionEndpoint "/settings/mfa/add/app" }}">Add MFA App</a>
              <a class="waves-effect waves-light btn modal-trigger" href="{{ pathjoin .ActionEndpoint "/settings/mfa/add/u2f" }}">Add U2F Key</a>
            </div>
          </div>
          <div class="row">
            {{ if .Data.mfa_devices }}
            <p>List of registered MFA devices</p>
            {{ else }}
            <p>No registered MFA devices found</p>
            {{ end }}
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
                      <input id="mfacode1" name="mfacode1" type="text" class="validate" pattern="[A-Za-z0-9]{4,8}"
                        title="Authentication code should contain maximum of 25 characters and consists of A-Z, a-z, and 0-9 characters."
                        required />
                      <label for="mfacode1">Authentication Code 1</label>
                    </div>
                    <div class="input-field">
                      <input id="mfacode2" name="mfacode2" type="text" class="validate" pattern="[A-Za-z0-9]{4,8}"
                        title="Authentication code should contain maximum of 25 characters and consists of A-Z, a-z, and 0-9 characters."
                        required />
                      <label for="mfacode2">Authentication Code 2</label>
                    </div>
                  </div>
                  <div class="col s12 m6 l6">
                    <div class="center-align"><img src="{{ pathjoin .ActionEndpoint "/settings/mfa/barcode/" .Data.code_uri_encoded }}.png" alt="QR Code" /></div>
                    <div class="center-align"><a href="{{ .Data.code_uri }}">Link</a></div>
                  </div>
                </div>
              </div>
              <div class="row right">
                <button type="submit" name="submit" class="btn waves-effect waves-light">Add
                  <i class="material-icons left">send</i>
                </button>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "mfa-add-u2f" }}
            <form action="{{ pathjoin .ActionEndpoint "/settings/mfa/add/u2f" }}" method="POST">
              <div class="row">
                <h1>Add U2F Security Key</h1>
                <div class="row">
                  <div class="col s12 m6 l6">
                    <p>Please add your U2F (USB, NFC, or Bluetooth) Security Key, e.g. Yubikey.</p>
                    <p>If your MFA application supports scanning QR codes, scan the following image with its camera.</p>
                    <p>Next, enter two consecutive authentication codes in the boxes below and click "Add" below.</p>
                    <div class="input-field">
                      <input id="mfacode1" name="mfacode1" type="text" class="validate" pattern="[A-Za-z0-9]{4,8}"
                        title="Authentication code should contain maximum of 25 characters and consists of A-Z, a-z, and 0-9 characters."
                        required />
                      <label for="mfacode1">Authentication Code 1</label>
                    </div>
                    <div class="input-field">
                      <input id="mfacode2" name="mfacode2" type="text" class="validate" pattern="[A-Za-z0-9]{4,8}"
                        title="Authentication code should contain maximum of 25 characters and consists of A-Z, a-z, and 0-9 characters."
                        required />
                      <label for="mfacode2">Authentication Code 2</label>
                    </div>
                  </div>
                </div>
              </div>
              <div class="row right">
                <button type="submit" name="submit" class="btn waves-effect waves-light">Add
                  <i class="material-icons left">send</i>
                </button>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "passwords" }}
            <p>The {{ .Data.view }} view is under construction.</p>
          {{ end }}
          {{ if eq .Data.view "misc" }}
            <p>The {{ .Data.view }} view is under construction.</p>
          {{ end }}
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js" integrity="sha256-U/cHDMTIHCeMcvehBv1xQ052bPSbJtbuiw4QA9cTKz0=" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.18.1/highlight.min.js" integrity="sha256-eOgo0OtLL4cdq7RdwRUiGKLX9XsIJ7nGhWEKbohmVAQ=" crossorigin="anonymous"></script>
    <script>
    </script>
  </body>
</html>`,
}
