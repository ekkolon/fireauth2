# Step 2: Exchange an Authorization Code for an Access Token

```http
GET /callback?code=<AUTHORIZATION_CODE>&state=<CSRF_TOKEN>
```

The `/callback` endpoint is invoked after the user grants consent via Google’s OAuth2 authorization screen. Its role is to securely complete the authorization code exchange and redirect the user back to the application with a valid identity.

As I outlined in the [Authorization section](/docs/02_authorization.md), before exchanging the authorization code for an access token, two critical validations are required:

## A. Verifying the Integrity of the Authorization Request

In order to ensure the legitimacy of the callback, the server retrieves and validates the short-lived session metadata stored in the **httpOnly** cookie during the initial `/authorize` step. The `state` parameter returned in the query string must exactly match the value stored in the session. A mismatch indicates a possible CSRF attempt or session tampering and must result in immediate rejection of the request.

In addition, the `code_verifier` stored in the session is retrieved and used as part of the PKCE validation during the code exchange, ensuring that the entity redeeming the code is the same that initiated the request.

## B. Validating the Authorization Code and Token Response

Once the session checks pass, the server exchanges the received `authorization code` with Google’s token endpoint, supplying the original `code_verifier` as required by the PKCE specification. A successful exchange yields both an `access_token` and an `id_token`.

The `id_token`, a signed JSON Web Token (JWT), is then cryptographically validated:

- The `iss` (issuer) claim must match Google's trusted issuer value (`https://accounts.google.com`).
- The `aud` (audience) claim must correspond to your OAuth client ID.
- The token's signature must be verified using Google’s published public keys (JWKS).
- Its `exp` (expiration) and `iat` (issued at) claims must be reasonable and current.

Only after all checks pass is the user considered authenticated. At this point, application-specific session handling may begin, such as issuing your own session cookie or storing the user’s identity in your backend.

## Redirecting the user back your application

**fireauth2** redirects the user back to the encoded absolute URL specified by the `redirect_uri` query parameter in the initial request to the `/authorize` endpoint.

> **NOTE**
>
> The `redirect_uri` query parameter is optional and is inferred by the `Referer` header of the request if not specified.
>
> Keep in mind, that in **fireauth2** this parameter **is not** the callback redirect URL of the OAuth process, but the final destination URL to your application an authenticated user is redirected to.
>
> It is an error if the `redirect_uri`:
>
> - is not an absolute URL
> - is malformed and thus could not be safely url-decoded
> - could not be determined, either because it could not be inferred via the `Referer` header or was not specified as query parameter in the initial request to the `/authorize` endpoint.
>
> Additionally, the provided URL **must** be specified in the Google OAuth Client configuration via the Google Cloud Platform.

The result of this authorization step is a `302 Found` redirection to the `redirect_uri` that includes the following payload as parameters in the URL's fragment:

```json
# Example 
{
    "access_token": "ya29.a0AWY...", // Opaque token
    "expires_in": 3600, // 1 hour
    "issued_at": 1759485825 // UNIX timestamp
}

```

On the client-side, the destination URL your authenticated users are redirected to may look like this:

```http
https://example.com/auth/signin#access_token=<ACCESS_TOKEN>&expires_in=3600&issued_at=1759485825
```

---

This two-phase verification - binding the auth request to the session and validating the token’s origin - is essential for maintaining trust and resisting common threats like CSRF, token injection, and session fixation. In this model, **fireauth2** acts not just as a proxy to Google's identity layer, but as a secure gateway enforcing all necessary checks before any (authenticated) session is established.
