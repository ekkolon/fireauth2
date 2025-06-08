use std::ops::Deref;

use fireauth2::GoogleOAuthClient;

use super::redirect_uri::RedirectUrl;

#[derive(Clone)]
pub struct FireAuth2(GoogleOAuthClient);

impl Deref for FireAuth2 {
    type Target = GoogleOAuthClient;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl actix_web::FromRequest for FireAuth2 {
    type Error = actix_web::Error;
    type Future = futures::future::Ready<actix_web::Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let redirect_uri = RedirectUrl::extract(req)
            .into_inner()
            .expect("RedirectUrl should be initialized on application startup");

        match req.app_data::<actix_web::web::Data<GoogleOAuthClient>>() {
            Some(data) => {
                let client = data
                    .as_ref()
                    .clone()
                    .with_redirect_uri(redirect_uri.inner_cloned());
                futures::future::ok(FireAuth2(client))
            }
            None => futures::future::err(
                actix_web::error::ErrorInternalServerError(
                    "GoogleOAuthClient should be initialized on application startup",
                ),
            ),
        }
    }
}
