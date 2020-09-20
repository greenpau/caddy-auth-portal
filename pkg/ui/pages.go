package ui

var defaultPageTemplates = map[string]string{
	"saml_login": `<!doctype html>
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
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
    <!-- Fonts and Icons -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.13.0/js/all.min.js" integrity="sha256-KzZiKy0DWYsnwMF+X1DvQngQ2/FxF7MF3Ff72XcpuPs=" crossorigin="anonymous"></script>
    {{ if .Authenticated }}
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.18.1/styles/atom-one-dark.min.css" integrity="sha256-GA29iW/iYj9FcuQQktvW45pRzHvZeFfgeFvA4tGVjpM=" crossorigin="anonymous" />
    {{ end }}
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@500&display=swap" rel="stylesheet">
    <style>
      body { font-size: 0.875rem; color: #5a6268, padding-top: 3rem; background-color: #e6eaed; font-family: 'Roboto', sans-serif; }
      @media screen and (max-width: 768px) {
        body { padding-top: 0px; }
      }
      h2 { color: #5a6268 !important; }
    </style>

  </head>
  <body class="bg-light">
    <div class="container">
      {{ if not .Authenticated }}
      <div class="row justify-content-center py-5">
        <div class="col-md-4 order-md-2 mb-4 card p-2">
          <div class="py-2 text-center">
            {{ if .LogoURL }}
            <img class="d-block mx-auto mb-2" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" width="72" height="72">
            {{ end }}
            <h2>{{ .Title }}</h2>
          </div>
          {{ if .Message }}
          <div class="alert alert-warning alert-dismissible fade show p-2" role="alert">
            <p>{{ .Message }}</p>
            <button type="button" class="close" data-dismiss="alert" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          {{ end }}

          {{range .PublicLinks}}
          <div class="pb-2 p-1">
            <a class="btn btn-primary btn-lg btn-block" href="{{ .Link }}">
              <span class="fab {{ .Style }}"></span> {{ .Title }}
            </a>
          </div>
          {{ end }}
        </div>
      </div>
      {{ else }}
      <div class="py-5 text-center col-md-4 offset-md-4">
        <h2>Welcome</h2>
        <p class="lead">Access the following services.</p>
        <ul class="list-group mb-3 pb-2">
          {{range .PrivateLinks}}
          <li class="list-group-item d-flex justify-content-between lh-condensed">
            <div>
              <h5 class="my-0"><a href="{{ .Link }}">{{ .Title }}</a></h6>
            </div>
          </li>
          {{ end }}
        </ul>
        <a href="{{ .ActionEndpoint }}?logout=true" class="btn btn-primary btn-lg active" role="button" aria-pressed="true">Logout</a>
      </div>
      {{ end }}
    </div>

    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
    {{ if .Authenticated }}
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.18.1/highlight.min.js" integrity="sha256-eOgo0OtLL4cdq7RdwRUiGKLX9XsIJ7nGhWEKbohmVAQ=" crossorigin="anonymous"></script>
    {{ end }}

  </body>
</html>`,
	"forms_login": `<!doctype html>
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
    <div class="container hide-on-med-and-up no-padding" style="height: 5vh !important;"></div>
    <div class="container hide-on-small-only no-padding" style="height: 10vh !important;"></div>
    <div class="container app-container">
      <div class="row">
        <div class="col s12 m8 offset-m2 l6 offset-l3 xl4 offset-xl4 app-card-container">
          <form action="{{ .ActionEndpoint }}" method="POST">
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
                <div class="input-field">
                  <input id="username" name="username" type="text" class="validate">
                  <label for="username">Username or Email</label>
                </div>
                <div class="input-field">
                  <input id="password" name="password" type="password" class="validate">
                  <label for="password">Password</label>
                </div>
              </div>
              <div class="card-action right-align">
                <button type="submit" name="submit" class="btn waves-effect waves-light btn-large">Login
                  <i class="material-icons left">send</i>
                </button>
              </div>
            </div>
            <div class="card card-large">
              <div class="card-content row">
                  <div class="helper-btn col s12 m6 l6 xl6">
                    <a href="{{ .ActionEndpoint }}/register" class="waves-effect waves-light btn-small">Register</a>
                  </div>
                  <div class="helper-btn col s12 m6 l6 xl6">
                    <a href="{{ .ActionEndpoint }}/forgot" class="waves-effect waves-light btn-small">Forgot Password?</a>
                  </div>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
    <!-- Optional JavaScript -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js" integrity="sha256-U/cHDMTIHCeMcvehBv1xQ052bPSbJtbuiw4QA9cTKz0=" crossorigin="anonymous"></script>
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
	"forms_portal": `<!doctype html>
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
    <div class="container hide-on-med-and-up no-padding" style="height: 5vh !important;"></div>
    <div class="container hide-on-small-only no-padding" style="height: 10vh !important;"></div>
    <div class="container app-container">
      <div class="row">
        <div class="col s12 m6 offset-m3 l4 offset-l4 app-card-container">
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
              <p>Access the following services.</p>
              <ul class="collection">
                {{range .PrivateLinks}}
                <li class="collection-item">
                  <a href="{{ .Link }}">{{ .Title }}</a>
                </li>
                {{ end }}
              </ul>
            </div>
            <div class="card-action right-align">
              <a href="{{ .ActionEndpoint }}/logout" class="navbtn-last">
                <button type="button" class="btn waves-effect waves-light navbtn active navbtn-last">
                  <span class="white-text"><i class="material-icons left">power_settings_new</i>Logout</span>
                </button>
              </a>
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
	"forms_ldap_login": `<!doctype html>
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
      select {
        font-family: 'Roboto', sans-serif;
        color: #155D56;
      }
      .app-background {
        background-color: #155D56;
      }
      .app-header {
        color: #EE6E73;
      }
      .helper-btn {
        margin-bottom: 0.5em;
      }
      .toast-error {
        // restyle post
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
        <div class="col s12 m8 offset-m2 l6 offset-l3 xl4 offset-xl4 app-card-container">
          <form action="{{ .ActionEndpoint }}" method="POST">
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
                <div class="input-field">
                  <input id="username" name="username" type="text" class="validate">
                  <label for="username">Username or Email</label>
                </div>
                <div class="input-field">
                  <input id="password" name="password" type="password" class="validate">
                  <label for="password">Password</label>
                </div>
                <div class="input-field">
                  <label>Domain</label>
                  <br /><br />
                  <select id="realm" name="realm" class="browser-default">
                    <option value="local" selected>Local</option>
                    <option value="contoso.com">CONTOSO.COM</option>
                  </select>
                </div>
              </div>
              <div class="card-action right-align">
                <button type="submit" name="submit" class="btn waves-effect waves-light btn-large">Login
                  <i class="material-icons left">send</i>
                </button>
              </div>
            </div>
            <div class="card card-large">
              <div class="card-content row">
                  <div class="helper-btn col s12 m6 l6 xl6">
                    <a href="{{ .ActionEndpoint }}?register=true" class="waves-effect waves-light btn-small">Register</a>
                  </div>
                  <div class="helper-btn col s12 m6 l6 xl6">
                    <a href="{{ .ActionEndpoint }}?forgot=true" class="waves-effect waves-light btn-small">Forgot Password?</a>
                  </div>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
    <!-- Optional JavaScript -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js" integrity="sha256-U/cHDMTIHCeMcvehBv1xQ052bPSbJtbuiw4QA9cTKz0=" crossorigin="anonymous"></script>
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
	"forms_whoami": `<!doctype html>
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
	      <pre><code class="json hljs">{{ .Data.token }}</code></pre>
            </div>
            <div class="card-action right-align">
              <a href="{{ .ActionEndpoint }}/portal">
	        <button type="button" class="btn waves-effect waves-light navbtn active">
                  <span class="white-text"><i class="material-icons left">home</i>Portal</span>
                </button>
              </a>
              <a href="{{ .ActionEndpoint }}/logout" class="navbtn-last">
                <button type="button" class="btn waves-effect waves-light navbtn active navbtn-last">
                  <span class="white-text"><i class="material-icons left">power_settings_new</i>Logout</span>
                </button>
              </a>
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
	"forms_register": `<!doctype html>
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
          <form action="{{ .ActionEndpoint }}/register" method="POST">
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
                    <a href="{{ .ActionEndpoint }}/termsandconditions">Terms and Conditions</a> and
                    <a href="{{ .ActionEndpoint }}/privacypolicy">Privacy Policy</a>.
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
	"forms_generic": `<!doctype html>
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
	"forms_settings": `<!doctype html>
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
                <a href="{{ .ActionEndpoint }}/portal">
                  <button type="button" class="btn waves-effect waves-light navbtn active">
                    <span class="white-text"><i class="material-icons navbar left">home</i>Portal</span>
                  </button>
                </a>
              </li>
              <li>
                <a href="{{ .ActionEndpoint }}/logout" class="navbtn-last">
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
            <a href="{{ .ActionEndpoint }}/settings/" class="collection-item{{ if eq .Data.view "general" }} active{{ end }}">General</a>
	    <a href="{{ .ActionEndpoint }}/settings/sshkeys" class="collection-item{{ if eq .Data.view "sshkeys" }} active{{ end }}">SSH Keys</a>
            <a href="{{ .ActionEndpoint }}/settings/gpgkeys" class="collection-item{{ if eq .Data.view "gpgkeys" }} active{{ end }}">GPG Keys</a>
            <a href="{{ .ActionEndpoint }}/settings/apikeys" class="collection-item{{ if eq .Data.view "apikeys" }} active{{ end }}">API Keys</a>
            <a href="{{ .ActionEndpoint }}/settings/mfa" class="collection-item{{ if eq .Data.view "mfa" }} active{{ end }}">MFA</a>
            <a href="{{ .ActionEndpoint }}/settings/passwords" class="collection-item{{ if eq .Data.view "passwords" }} active{{ end }}">Passwords</a>
            <a href="{{ .ActionEndpoint }}/settings/misc" class="collection-item{{ if eq .Data.view "misc" }} active{{ end }}">Miscellaneous</a>
          </div>
        </div>
        <div class="col s12 l9">
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
            <p>The {{ .Data.view }} view is under construction.</p>
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
    {{ if .Message }}
    <script>
    hljs.initHighlightingOnLoad();
    </script>
    {{ end }}
  </body>
</html>`,
}
