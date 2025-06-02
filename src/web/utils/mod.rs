use actix_web::HttpRequest;
use actix_web::http::header::REFERER;

pub fn get_referer_url(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get(REFERER)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
}
