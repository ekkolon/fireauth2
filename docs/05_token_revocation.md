# Revoking access and refresh tokens

```http
POST /revoke
```

Authenticated users may choose to explicitly sign out of your application, or your application may need to force a sign-out, for instance, in response to a security event or upon account deletion.

The `/revoke` endpoint accepts either an **access token** or **refresh token** in the request body and instructs Google’s OAuth 2.0 server to revoke it. This action immediately invalidates the token, preventing any future use of it to access protected resources or obtain new tokens.

To protect this operation, the user **must be authenticated** in Firebase Authentication. Therefore, a valid Firebase `idToken` must be provided in the `Authorization` header using the Bearer scheme.

Here is an example of such a request to revoke an *access token*:

```http
POST /revoke
Authorization: Bearer <FIREBASE_ID_TOKEN>
Content-Type: application/json

{
  "accessToken": "<ACCESS_TOKEN>"
}
```

Similarly, to revoke a *refresh token*:

```http
POST /revoke
Authorization: Bearer <FIREBASE_ID_TOKEN>
Content-Type: application/json

{
  "refreshToken": "<REFRESH_TOKEN>"
}
```

Upon receiving this request, the server performs the following steps:

1. **Verifies the Firebase ID token** in the Authorization header, ensuring that the user is currently authenticated and authorized to revoke the specified token.
2. **Validates the provided token** in the body to ensure it conforms to the expected format.
3. **Sends a request to Google’s token revocation endpoint**

4. **Returns an appropriate HTTP status** to the client
    - `200 OK` if the token was successfully revoked.
    - `400 Bad Request` if the token was malformed or already invalidated.
    - `401 Unauthorized` if the Firebase ID token was missing, expired, or invalid.

Revoking a **refresh token** also invalidates all access tokens derived from it.
Access tokens alone typically expire quickly, but revoking them may still be useful for immediate deauthorization.

After revocation, the client *should* also clear any local session state and perform a full logout. This specifically means to remove the *access token* from the chosen storage instance (e.g localStorage, indexedDB) **and** *signOut* from Firebase.
