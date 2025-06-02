use crate::GoogleOAuthClient;

use super::AppState;

impl actix_web::FromRequest for GoogleOAuthClient {
    type Error = actix_web::Error;
    type Future = futures::future::Ready<actix_web::Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let redirect_uri = match req.app_data::<actix_web::web::Data<AppState>>() {
            Some(wrapper) => {
                let app_state = wrapper.as_ref();
                let redirect_uri_result = app_state.get_redirect_uri_from_request(req);
                if let Err(err) = redirect_uri_result {
                    return futures::future::err(actix_web::error::ErrorInternalServerError(
                        err.to_string(),
                    ));
                };

                
                redirect_uri_result.unwrap()
            }
            None => {
                return futures::future::err(actix_web::error::ErrorInternalServerError(
                    "AppState missing",
                ));
            }
        };

        match req.app_data::<actix_web::web::Data<GoogleOAuthClient>>() {
            Some(client_wrapper) => {
                let client = client_wrapper
                    .as_ref()
                    .clone()
                    .with_redirect_uri(redirect_uri);
                futures::future::ok(client)
            }
            None => {
                futures::future::err(actix_web::error::ErrorInternalServerError(
                    "GoogleOAuthClient not initialized",
                ))
            }
        }
    }
}
