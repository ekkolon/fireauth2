# Step 1: Authorization

> **Note**
> This document outlines the server-side OAuth 2.0 authorization flow as implemented by fireauth2. While it introduces additional mechanisms for enhanced security and Firebase integration, it remains fully compliant with the OAuth 2.0 specification.

An OAuth 2.0 flow starts with a `GET` request to an authorization endpoint that is responsible for redirecting the user to an OAuth consent screen.

In **fireauth2**, this endpoint is available at:

```http
GET /authorize
```

This route accepts standard OAuth 2.0 query parameters, allowing you to tailor the behavior of the authorization request. For example:

```http
GET https://oauth.example.com/authorize?access_type=offline&prompt=consent&scope=<SCOPES...>
```

...requests an access token and a refresh token (due to `access_type=offline` and `prompt=consent`).

In contrast:

```http
GET https://oauth.example.com/authorize?access_type=online&prompt=select_account,consent&scope=<SCOPES...>
```

...redirects the user to Google’s account selection and consent screen. Only an access token will be issued in this case.

## Security Enhancements in fireauth2

To mitigate CSRF attacks, **fireauth2** generates a cryptographically secure random `state` parameter and binds it to the user's session.

Additionally, it uses **PKCE** (Proof Key for Code Exchange) by generating a high-entropy `code_verifier` and its derived `code_challenge`, ensuring the authorization code can only be redeemed by the initiator.

Before redirecting, **fireauth2** stores the session metadata — including `state` and `code_verifier` - in a short-lived, **httpOnly** cookie. This provides authenticity and integrity for the follow-up callback request.

<details>
  <summary><strong>Supported Query Parameters</strong></summary>

- **`access_type`** (default: `online`)  
  Determines whether your app can receive a refresh token.  
  - `online`: Only an access token is issued.  
  - `offline`: Both an access and a refresh token are issued (if `prompt=consent` is also set).

- **`prompt`** (default: `none`)  
  A space-delimited list of prompts that control user interaction.  
  - `none`: No prompt unless required.  
  - `consent`: Force user consent.  
  - `select_account`: Show account selector.

- **`scope`**  
  A **comma-delimited** list of [Google OAuth 2.0 scopes](https://developers.google.com/identity/protocols/oauth2/scopes) to request access for.  
  Example: `scope=email,profile,openid`

- **`login_hint`** (default: `null`)  
  If known, hints which user is authenticating. Helps pre-fill the login form.  
  Accepts either a Google email or a Google `sub` (user ID).

- **`include_granted_scopes`** (default: `true`)  
  If `true`, the OAuth server will include previously granted scopes in this authorization request, streamlining user experience.

</details>

For full context, refer to [Google’s server-side OAuth 2.0 guide](https://developers.google.com/identity/protocols/oauth2/web-server#obtainingaccesstokens).

To complete the OAuth authorization flow the next step is to [exchange the **authorization code** issued by Google's OAuth 2.0 server for an **access token**](/docs/03_exchange_authorization_code.md).
