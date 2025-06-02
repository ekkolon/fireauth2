#[macro_export]
macro_rules! impl_actix_from_request {
  (for $($t:ty),+) => {
      $(impl actix_web::FromRequest for $t {
        type Error = actix_web::Error;
        type Future = futures::future::Ready<actix_web::Result<Self, Self::Error>>;

        fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
            match req.app_data::<actix_web::web::Data<$t>>() {
                Some(wrapper) => futures::future::ok(wrapper.as_ref().clone()),
                None => futures::future::err(actix_web::error::ErrorInternalServerError(
                    "Structs must be initialized in application data in order to be extractable",
                )),
            }
        }
      })*
  }
}
