use actix_web::{get, App, HttpResponse, HttpServer};

#[get("/plaintext")]
async fn plaintext() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain")
        .body("Hello, World!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(plaintext))
        .workers(1)
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}
