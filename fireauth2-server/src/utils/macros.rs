/// Implements `FromRequest` for one or more types that are expected to be injected
/// into Actix Web's application data (`web::Data<T>`).
///
/// # Purpose
/// This macro allows types to be extracted from requests automatically if they
/// were registered in the Actix application using `.app_data(web::Data::new(...))`.
///
/// # Example
/// ```no_run
/// impl_actix_from_request!(for MyService, AnotherType);
/// ```
///
/// If the type is not registered in application data, an internal server error
/// will be returned with a helpful message including the type name.
///
/// # Limitations
/// - The type must implement `Clone` as `.clone()` is called on the data reference.
/// - The error type is always `actix_web::Error`.
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
                    format!(
                      "{} must be initialized in application data in order to be extractable",
                      std::any::type_name::<$t>()
                    ),
                )),
            }
        }
      })*
  }
}
