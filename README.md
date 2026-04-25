# simple-traefik-oidc

This is a _simple_ [traefik](https://github.com/traefik/traefik) plugin for gating web services behind an OIDC provider such as [authentik](https://github.com/goauthentik/authentik). The plugin is designed to reduce attack surface and prevent exploitation from internet-wide scanning if you e.g. update a vulnerable application too late.

Compared to similar plugins, this plugin focuses on _compatibility_ and _performance_, at the cost of security. In particular, protections against attacks such as cross-site request forgery are _intentionally_ weak because they can interfere with service functionality. This plugin simply sets and checks a session cookie. It is **no substitute for app-level logins**.

> [!CAUTION]
> This plugin is designed to only defend against broad internet-wide scans; To protect against targeted attacks (e.g. CSRF), the backend application still needs to be secure.

## How it works

_simple-traefik-oidc_ is very straight-forward: When a user tries to access the site, the plugin checks if an unexpired session cookie with a properly authenticated payload is present. If the session cookie is valid, the request goes through to the backend application. If it is not valid, the user is redirected to the OIDC provider and let in when she completes the login.

There is currently no functionality to check the identity of the user.

## Configuration

```toml
[experimental.plugins.simple-traefik-oidc]
moduleName = "github.com/yawkat/simple-traefik-oidc"
version = "<version number>"

[http.middlewares.authentik-middleware.plugin.simple-traefik-oidc]
providerUrl = "https://authentik.yawk.at/application/o/traefik"
clientId = "<client ID>"
clientSecret = "<client secret>"
sessionKey = "<a random string used for encrypting and authenticating the session cookie>"
host = "<host of the website>"
excludedUrls = ["<optional: paths to skip authentication for>"]
```
