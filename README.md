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

The quickest way to start using this project is by building a Docker image directly from this repository - assuming you have the [Docker CLI](https://www.docker.com/products/cli/) installed locally.

### 1. Build

```bash
docker build -t fireauth2:latest https://github.com/ekkolon/fireauth2.git#main:fireauth2-server
```

### 2. Run

> ℹ️ Copy the contents of [.env.example](./.env.example) and replace the placeholder values with your own.

```bash
docker run --env-file .env -p 8080:8080 fireauth2:latest
```

## Development

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

    fireauth2 — Google OAuth 2.0 flows with first-class Firebase support
    Copyright (C) 2025  Nelson Dominguez

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
