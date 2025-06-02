// TODO: Tests, tests, tests

// Core modules
mod client;
mod error;
mod models;
mod utils;

// Re-export core modules for easy access
pub use client::*;
pub use error::*;
pub use utils::*;

// Web-related functionality (handlers, routes, etc.)
pub mod web;
