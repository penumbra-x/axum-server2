[![Crates.io License](https://img.shields.io/crates/l/axum-server2)](./LICENSE)
[![Crates.io](https://img.shields.io/crates/v/axum-server2)](https://crates.io/crates/axum-server2)
[![Docs](https://img.shields.io/crates/v/axum-server2?color=blue&label=docs)](https://docs.rs/axum-server2/)

# axum-server2

axum-server2 is a [hyper] server implementation designed to be used with [axum] framework.

This project is maintained by community independently from [axum].

> This branch applies a patched version of [hyper](https://github.com/penumbra-x/hyper) and [boringssl](https://github.com/penumbra-x/boring)

## Features

- HTTP/1 and HTTP/2
- HTTPS through [rustls]、[openssl]、[boringssl].
- High performance through [hyper].
- Using [tower] make service API.
- Very good [axum] compatibility. Likely to work with future [axum] releases.

## Usage Example

A simple hello world application can be served like:

```rust
use axum::{routing::get, Router};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(|| async { "Hello, world!" }));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    axum_server2::bind(addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

You can find more examples [here](/examples).

## Minimum Supported Rust Version

axum-server2's MSRV is `1.49`.

## Safety

This crate uses `#![forbid(unsafe_code)]` to ensure everything is implemented in 100% safe Rust.

## License

This project is licensed under the [MIT license](LICENSE).

[axum]: https://crates.io/crates/axum
[hyper]: https://crates.io/crates/hyper
[rustls]: https://crates.io/crates/rustls
[tower]: https://crates.io/crates/tower
[openssl]: https://crates.io/crates/openssl
[boringssl]: https://crates.io/crates/rboring

## Accolades

The project is based on a fork of [axum-server](https://github.com/programatik29/axum-server).