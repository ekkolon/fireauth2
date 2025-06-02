use actix_web::{App, HttpServer, middleware, web::Data};
use fireauth2::GoogleOAuthClient;
use fireauth2::web::AppState;
use fireauth2::web::repositories::GoogleUserRepository;
use firestore::FirestoreDb;
use std::sync::Arc;

#[actix_web::main]
async fn main() -> fireauth2::Result<()> {
    // Initialize environment variables and logging
    fireauth2::env::init()?;
    fireauth2::logger::init()?;

    // Determine the socket address to bind the server
    let socket_addr = fireauth2::env::get_socket_addrs()?;

    // Setup shared application state
    let app_state = Arc::new(AppState::from_env()?);
    let google_oauth = Arc::new(GoogleOAuthClient::new()?);

    // Initialize Firestore client using the Google project ID
    let project_id = google_oauth.project_id();
    let firestore = FirestoreDb::new(project_id).await?;

    // Create Google user repository with Firestore and collection name
    let google_user_repo = Arc::new(GoogleUserRepository::new(
        firestore,
        app_state.firestore_collection_name(),
    )?);

    log::info!("Starting HTTP server on {}", socket_addr);

    HttpServer::new(move || {
        App::new()
            .app_data(Data::from(app_state.clone()))
            .app_data(Data::from(google_oauth.clone()))
            .app_data(Data::from(google_user_repo.clone()))
            .wrap(actix_cors::Cors::permissive()) // TODO: tighten CORS in production
            .wrap(middleware::Logger::default())
            .wrap(middleware::NormalizePath::trim())
            .configure(fireauth2::web::routes::configure)
    })
    .workers(2)
    .bind(socket_addr)?
    .run()
    .await?;

    Ok(())
}
