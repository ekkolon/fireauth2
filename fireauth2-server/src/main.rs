//! Rust server for handling Google OAuth 2.0 flows with first-class
//! Firebase Authentication support.

mod error;
mod models;
mod utils;
mod web;

pub use error::*;

use crate::web::AppState;
use fireauth2::GoogleOAuthClient;

use actix_firebase_auth::FirebaseAuth;
use actix_web::{App, HttpServer, middleware, web::Data};
use std::sync::Arc;

#[actix_web::main]
async fn main() -> Result<()> {
    // Initialize environment variables and logging
    utils::env::init()?;
    utils::logger::init()?;

    // Determine the socket address to bind the server
    let socket_addr = utils::env::get_socket_addrs()?;

    // Setup shared application state
    let app_state = AppState::from_env().map(Arc::new)?;
    let google_auth = GoogleOAuthClient::new().await.map(Arc::new)?;

    // Initialize Firestore client using the Google project ID
    let project_id = google_auth.project_id();
    let firebase_auth = FirebaseAuth::new(project_id).await.map(Arc::new)?;

    log::info!("Starting HTTP server on {}", socket_addr);

    HttpServer::new(move || {
        App::new()
            .app_data(Data::from(app_state.clone()))
            .app_data(Data::from(firebase_auth.clone()))
            .app_data(Data::from(google_auth.clone()))
            .wrap(actix_cors::Cors::permissive()) // TODO: tighten CORS in production
            .wrap(middleware::Logger::default())
            .wrap(middleware::NormalizePath::trim())
            .configure(web::routes::configure)
    })
    .workers(2)
    .bind(socket_addr)?
    .run()
    .await?;

    Ok(())
}
