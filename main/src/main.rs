use hyper::service::{make_service_fn, service_fn};
use hyper::{header, Method, StatusCode};
use hyper::{Body, Request, Response, Server};
use serde_json::json;
use std::env;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;

async fn api_healthcheck() -> Result<Response<Body>> {
    let json = json!({
        "status": "healthy",
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json.to_string()))
        .unwrap())
}

async fn method_not_allowed() -> Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .body(Body::from(Vec::new()))
        .unwrap())
}

async fn router(req: Request<Body>) -> Result<Response<Body>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => api_healthcheck().await,
        _ => method_not_allowed().await,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let port = env::var("AUTH_API_PORT").unwrap_or_else(|_| 5000.to_string());
    let addr = format!("0.0.0.0:{}", port).parse().unwrap();

    let router = make_service_fn(move |_| async { Ok::<_, GenericError>(service_fn(router)) });

    let server = Server::bind(&addr).serve(router);

    println!("AtomicDEX Auth API serving on http://{}", addr);

    server.await?;

    Ok(())
}
