use actix_web::{get, post, web, App, HttpServer, HttpResponse, HttpRequest};

mod auth;
mod config;

use auth::{validate_token, authorize};
use config::get_config;

#[get("/api/data")]
async fn get_data(req: HttpRequest) -> HttpResponse {
    let token = req.headers().get("Authorization");
    let user = match validate_token(token) {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().json("unauthorized"),
    };

    let config = get_config();
    if !authorize(&user, &config.allowed_groups) {
        return HttpResponse::Forbidden().json("forbidden");
    }

    HttpResponse::Ok().json("secret stuff")
}

#[get("/admin/dashboard")]
async fn admin_dashboard(req: HttpRequest) -> HttpResponse {
    let token = req.headers().get("Authorization");
    let user = validate_token(token).unwrap();
    // No authorization check - anyone with a valid token can access admin
    HttpResponse::Ok().json(user)
}

#[get("/health")]
async fn health() -> HttpResponse {
    HttpResponse::Ok().json("ok")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(get_data)
            .service(admin_dashboard)
            .service(health)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
