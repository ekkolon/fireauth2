use std::ops::Deref;

use fireauth2::FireAuthClient;

use super::redirect_uri::RedirectUrl;

#[derive(Clone)]
pub struct FireAuth(FireAuthClient);

impl Deref for FireAuth {
    type Target = FireAuthClient;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl actix_web::FromRequest for FireAuth {
    type Error = actix_web::Error;
    type Future = futures::future::Ready<actix_web::Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let redirect_uri = RedirectUrl::extract(req)
            .into_inner()
            .expect("RedirectUrl should be initialized on application startup");

        match req.app_data::<actix_web::web::Data<FireAuthClient>>() {
            Some(data) => {
                let client = data
                    .as_ref()
                    .clone()
                    .with_redirect_uri(redirect_uri.inner_cloned());
                futures::future::ok(FireAuth(client))
            }
            None => futures::future::err(
                actix_web::error::ErrorInternalServerError(
                    "GoogleOAuthClient should be initialized on application startup",
                ),
            ),
        }
    }
}
