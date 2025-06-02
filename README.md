# fireauth2

An OAuth 2.0 Rust server for Google Sign-In with first-class Firebase Authentication support.

> ⚠️ **Experimental Software**
>
> This project is in an experimental state and **not production-ready**.  
> It may lack features, contain bugs, and is subject to **breaking changes without notice**.
>
> You are welcome to fork and adapt the implementation to suit your specific requirements.

**You may be looking for**:

- [Overview](#overview)
- [Getting Started](#getting-started)
- [License](#license)

For more details, see the [Documentation](/docs/01_getting_started.md) section.

## Overview

**fireauth2** is designed for developers who:

- Use **Firebase Authentication** as their primary identity platform  
- Require **secure, long-lived OAuth sessions** to interact with **Google APIs** on behalf of users  
- Prefer **server-side handling** of sensitive credentials and authorization flows  
- Need robust **CSRF protection** and **PKCE-based request integrity**

---

**fireauth2** bridges the gap between Google’s OAuth 2.0 authorization framework and Firebase’s identity model. It facilitates:

- Google Sign-In via the **Authorization Code Flow**
- Seamless **access token refresh** via the `/token` endpoint
- **Token revocation** for logout and permission reset

It is ideal for applications that require:

- Calling Google APIs like Calendar, Drive, or Gmail on behalf of signed-in users  
- Persistent login without re-prompting for consent  
- A server-controlled OAuth lifecycle with minimal client-side logic

## Getting Started

Follow these steps to clone, build, and run **fireauth2** locally for development and testing purposes.

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (recommended: latest stable)
- [Git](https://git-scm.com/)
- [A Firebase project](https://console.firebase.google.com/) (A Firebase Project **is** a Google Cloud Project)
- OAuth 2.0 credentials set up for the specified Google Cloud project

### Clone the repository

```bash
git clone https://github.com/ekkolon/fireauth2.git
cd fireauth2
```

If your using the GitHub CLI:

```bash
gh repo clone ekkolon/fireauth2
cd fireauth2
```

### Configure environment variables

> ⚠️ **Important**: Never commit your credentials or secrets to version control.
Make sure your .gitignore properly excludes sensitive files like .env to keep them safe.

Copy the example environment file and edit it to include your **base64-encoded** Google OAuth client config and the path to your Google Service Account credentials:

```bash
cp .env.example .env
# Edit `.env` to set GOOGLE_APPLICATION_CREDENTIALS, GOOGLE_OAUTH_CLIENT_CONFIG, and other variables
```

>⚠️ **Security Tip**:
>
> When base64-encoding your OAuth Client credentials, **avoid using untrusted third-party tools**.
>
> If you're on Linux, prefer using the built-in [**base64 command-line utility**](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html#base64-invocation) from the GNU coreutils package to ensure safe and reliable encoding.

### Build and run the server

To build and run the server in development mode:

```bash
cargo run
```

This will start the server on the default port (usually <http://localhost:8080>).

### Access the application

Open your browser and start the authorization process, for example:

```http
http://localhost:8080/authorize?access_type=offline&prompt=consent&scope=<SCOPES...>
```

This will start the OAuth2 flow by redirecting you to Google’s consent screen.

> ⚠️ Important: Make sure to *urlencode* the space-delimited OAuth scopes.

### Running in release mode

For optimized builds suitable for staging or production testing:

```bash
cargo run --release
```

## License

Licensed under either of

- [MIT license](https://spdx.org/licenses/MIT.html) (see [LICENSE-MIT](/LICENSE-MIT)) or
- [Apache License, Version 2.0](https://spdx.org/licenses/Apache-2.0.html) (see [LICENSE-APACHE](/LICENSE-APACHE))

at your option.

## Contributions

Unless you explicitly stated otherwise, any contribution intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
