//! # FireAuth2 — Google OAuth2 & Firebase Authentication Library
//!
//! This crate provides a comprehensive and strongly-typed Rust interface
//! for integrating Google OAuth2 authentication flows with first-class Firebase
//! Authentication support.
//!
//! ## Features
//!
//! - OAuth2 client handling including PKCE and CSRF protection.
//! - Structured request and response models for token exchange, refresh, and revocation.
//! - Support for Google-specific OAuth2 extensions like `id_token` handling.
//! - Configurable authorization requests with support for extra parameters.
//! - Convenience builders for constructing complex OAuth2 request configurations.
//! - **First-class Firebase Authentication integration:**  
//!   - Automatic syncing of refresh tokens to Firestore for persistent session management.  
//!   - Utilities for handling Firebase user identity and token lifecycle management.
//!
//! ## Modules
//!
//! - `client`: Core OAuth2 client implementations and helpers for Google OAuth2 flows, including Firebase Authentication integration.
//! - `error`: Error handling types and utilities used throughout the crate.
//! - `models`: Data structures representing OAuth2 payloads, tokens, config options, and Firebase token extensions.
//! - `repositories`: Persistence layer abstractions such as token storage, revocation, and Firestore syncing.
//!
//! ## Usage
//!
//! This crate re-exports key types from `oauth2` such as `CsrfToken` and `PkceCodeVerifier`
//! to simplify usage.
//!
//! ```rust
//! use fireauth2::{CsrfToken, PkceCodeVerifier};
//! use fireauth2::GoogleOAuthClient;
//!
//! // TODO: Initialize client, perform authorization code exchange
//! ```
//!
//! ## Customization
//!
//! The crate supports customization of OAuth2 requests via additional parameters
//! and token introspection support, plus fine-grained control over Firestore token syncing.
//!
//! ## Example
//!
//! See the `client` module for examples demonstrating OAuth2 authorization code
//! exchange, token refresh, revocation workflows, and Firebase Authentication token management.
//!
//! ---
//!
//! If you encounter any issues or want to contribute, please open an issue or
//! pull request on the GitHub repository.
//!

mod client;
mod error;
mod models;
mod repositories;

// Re-export core modules for easy access
pub use client::*;
pub use error::*;
pub use models::*;

// Re-export oauth types
pub use oauth2::{CsrfToken, PkceCodeVerifier};
