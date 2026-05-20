use std::convert::Infallible;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

const BODY: &[u8] = b"Hello, World!";

async fn handle(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONTENT_LENGTH, BODY.len())
        .body(Full::new(Bytes::from_static(BODY)))
        .unwrap())
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current_thread");
    rt.block_on(async {
        let addr: SocketAddr = ([0, 0, 0, 0], 8080).into();
        let listener = TcpListener::bind(addr).await.expect("bind");
        loop {
            let (stream, _) = listener.accept().await.expect("accept");
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(io, service_fn(handle))
                    .await;
            });
        }
    });
}
