use actix_web::web;

mod authorize;
mod callback;
mod introspect;
mod revoke;
mod token;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(authorize::authorize)
        .service(callback::exchange_authorization_code)
        .service(revoke::revoke_token)
        .service(token::exchange_refresh_token)
        .service(introspect::introspect);
}
