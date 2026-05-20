use axum::{
    http::header::{HeaderValue, CONTENT_TYPE},
    response::IntoResponse,
    routing::get,
    Router,
};

async fn plaintext() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, HeaderValue::from_static("text/plain"))],
        "Hello, World!",
    )
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current_thread");
    rt.block_on(async {
        let app = Router::new().route("/plaintext", get(plaintext));
        let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
            .await
            .expect("bind");
        axum::serve(listener, app).await.expect("serve");
    });
}
