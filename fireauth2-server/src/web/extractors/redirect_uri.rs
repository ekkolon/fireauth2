use std::ops::Deref;

use actix_web::HttpRequest;
use url::Url;

use crate::web::AppState;

pub struct RedirectUrl(Url);

impl Deref for RedirectUrl {
    type Target = Url;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl RedirectUrl {
    pub fn inner_cloned(&self) -> Url {
        self.0.clone()
    }
}

pub fn get_redirect_uri_from_request(
    req: &HttpRequest,
    redirect_uri_path: &str,
) -> crate::Result<url::Url> {
    let info = req.connection_info();
    let scheme = info.scheme();
    let host = info.host();
    let origin = format!("{}://{}", scheme, host);
    let mut origin_url = url::Url::parse(&origin)?;
    origin_url.set_path(redirect_uri_path);
    Ok(origin_url)
}

impl actix_web::FromRequest for RedirectUrl {
    type Error = actix_web::Error;
    type Future = futures::future::Ready<actix_web::Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let redirect_uri = match req
            .app_data::<actix_web::web::Data<AppState>>()
        {
            Some(wrapper) => {
                let app_state = wrapper.as_ref();
                let redirect_uri_result = get_redirect_uri_from_request(
                    req,
                    app_state.redirect_uri_path(),
                );

                if let Err(err) = redirect_uri_result {
                    return futures::future::err(
                        actix_web::error::ErrorInternalServerError(
                            err.to_string(),
                        ),
                    );
                };

                redirect_uri_result.unwrap()
            }
            None => {
                return futures::future::err(
                    actix_web::error::ErrorInternalServerError(
                        "AppState should be initialized on application startup",
                    ),
                );
            }
        };

        futures::future::ok(RedirectUrl(redirect_uri))
    }
}
