//! Run with `cargo run --all-features --example boringssl_server` command.
//!
//! To connect through browser, navigate to "https://localhost:3000" url.

use axum::{routing::get, Router};
use axum_server2::{self as axum_server2, tls_boringssl::BoringSSLConfig};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(|| async { "Hello, world!" }));

    let config = BoringSSLConfig::from_pem_file(
        "examples/self-signed-certs/cert.pem",
        "examples/self-signed-certs/key.pem",
    )
    .unwrap();

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    axum_server2::bind_boringssl(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
