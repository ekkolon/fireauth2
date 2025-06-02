# Exchanging a refresh token for an access token

```http
POST /token
```

The `/token` endpoint is used to obtain a new access token by presenting a valid **refresh token**. This is essential in long-lived sessions where the original access token has expired, but the user remains authenticated (in Firebase).

To protect this operation, the user **must be authenticated** in Firebase Authentication. Therefore, a valid Firebase `idToken` must be provided in the `Authorization` header using the Bearer scheme.

Unlike the initial authorization flow, this exchange does **not** require user interaction and is performed entirely server-side. However, the application **must implement logic** to detect when access tokens are nearing expiration and trigger this exchange proactively. This is commonly handled via a refresh scheduler, token expiration listener, or HTTP middleware that retries failed requests.
