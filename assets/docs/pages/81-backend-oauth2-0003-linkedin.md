#### LinkedIn

First, browse to https://www.linkedin.com/developers/apps/new and create an application.

![LinkedIn Developers - New Application](./assets/docs/images/oauth2_linkedin_new_app.png)

Next, note the "Client Secret"


![LinkedIn Developers - Auth Screen](./assets/docs/images/oauth2_linkedin_auth_screen.png)


After that, add "redirect URLS":

```
https://localhost:8443/auth/oauth2/linkedin/authorization-code-callback
```

![LinkedIn Developers - Auth Screen - Redirect URLs](./assets/docs/images/oauth2_linkedin_redirect_url.png)

Next, browse to "Products" tab and enabled "Sign In with LinkedIn":

![LinkedIn Developers - Products Screen](./assets/docs/images/oauth2_linkedin_products_screen.png)

References:
* [LinkedIn - LinkedIn API Documentation - Authentication - Authorization Code Flow](https://docs.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow)
* [LinkedIn - Consumer Solutions Platform - Integrations - Sign In with LinkedIn](https://docs.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin)
