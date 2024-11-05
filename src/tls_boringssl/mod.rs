//! Tls implementation using [`openssl`]
//!
//! # Example
//!
//! ```rust,no_run
//! use axum::{routing::get, Router};
//! use axum_server2::tls_boringssl::BoringSSLConfig;
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() {
//!     let app = Router::new().route("/", get(|| async { "Hello, world!" }));
//!
//!     let config = BoringSSLConfig::from_pem_file(
//!         "examples/self-signed-certs/cert.pem",
//!         "examples/self-signed-certs/key.pem",
//!     )
//!     .unwrap();
//!
//!     let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
//!     println!("listening on {}", addr);
//!     axum_server2::bind_boringssl(addr, config)
//!         .serve(app.into_make_service())
//!         .await
//!         .unwrap();
//! }
//! ```

use self::future::BoringSSLSSLAcceptorFuture;
use crate::{
    accept::{Accept, DefaultAcceptor},
    server::Server,
};
use boring::ssl::{self, Error as BoringSSLError, SslOptions, SslVersion};
use boring::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};
use std::{convert::TryFrom, fmt, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_boring::SslStream;

pub mod future;

/// Create a TLS server that will be bound to the provided socket with a configuration. See
/// the [`crate::tls_openssl`] module for more details.
pub fn bind_boringssl(addr: SocketAddr, config: BoringSSLConfig) -> Server<BoringSSLAcceptor> {
    let acceptor = BoringSSLAcceptor::new(config);

    Server::bind(addr).acceptor(acceptor)
}

/// Tls acceptor that uses OpenSSL. For details on how to use this see [`crate::tls_openssl`] module
/// for more details.
#[derive(Clone)]
pub struct BoringSSLAcceptor<A = DefaultAcceptor> {
    inner: A,
    config: BoringSSLConfig,
    handshake_timeout: Duration,
}

impl BoringSSLAcceptor {
    /// Create a new OpenSSL acceptor based on the provided [`OpenSSLConfig`]. This is
    /// generally used with manual calls to [`Server::bind`]. You may want [`bind_openssl`]
    /// instead.
    pub fn new(config: BoringSSLConfig) -> Self {
        let inner = DefaultAcceptor::new();

        #[cfg(not(test))]
        let handshake_timeout = Duration::from_secs(10);

        // Don't force tests to wait too long.
        #[cfg(test)]
        let handshake_timeout = Duration::from_secs(1);

        Self {
            inner,
            config,
            handshake_timeout,
        }
    }

    /// Override the default TLS handshake timeout of 10 seconds.
    pub fn handshake_timeout(mut self, val: Duration) -> Self {
        self.handshake_timeout = val;
        self
    }
}

impl<A, I, S> Accept<I, S> for BoringSSLAcceptor<A>
where
    A: Accept<I, S>,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = SslStream<A::Stream>;
    type Service = A::Service;
    type Future = BoringSSLSSLAcceptorFuture<A::Future, A::Stream, A::Service>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner_future = self.inner.accept(stream, service);
        let config = self.config.clone();

        BoringSSLSSLAcceptorFuture::new(inner_future, config, self.handshake_timeout)
    }
}

impl<A> fmt::Debug for BoringSSLAcceptor<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoringSSLAcceptor").finish()
    }
}

/// BoringSSL configuration.
#[derive(Clone)]
pub struct BoringSSLConfig {
    acceptor: Arc<SslAcceptor>,
}

impl BoringSSLConfig {
    /// This helper will established a TLS server based on strong cipher suites
    /// from a PEM formatted certificate and key.
    pub fn from_pem_file<A: AsRef<Path>, B: AsRef<Path>>(
        cert: A,
        key: B,
    ) -> Result<Self, BoringSSLError> {
        let mut tls_builder = default_acceptor_builder()?;

        tls_builder.set_certificate_file(cert, SslFiletype::PEM)?;

        tls_builder.set_private_key_file(key, SslFiletype::PEM)?;

        tls_builder.check_private_key()?;

        let acceptor = Arc::new(tls_builder.build());

        Ok(BoringSSLConfig { acceptor })
    }

    /// This helper will established a TLS server based on strong cipher suites
    /// from a PEM formatted certificate chain and key.
    pub fn from_pem_chain_file<A: AsRef<Path>, B: AsRef<Path>>(
        chain: A,
        key: B,
    ) -> Result<Self, BoringSSLError> {
        let mut tls_builder = default_acceptor_builder()?;

        tls_builder.set_certificate_chain_file(chain)?;

        tls_builder.set_private_key_file(key, SslFiletype::PEM)?;

        tls_builder.check_private_key()?;

        let acceptor = Arc::new(tls_builder.build());

        Ok(BoringSSLConfig { acceptor })
    }
}

impl TryFrom<SslAcceptorBuilder> for BoringSSLConfig {
    type Error = BoringSSLError;

    /// Build the [`BoringSSLConfig`] from an [`SslAcceptorBuilder`]. This allows precise
    /// control over the settings that will be used by BoringSSL in this server.
    ///
    /// # Example
    /// ```
    /// use axum_server2::tls_boringssl::BoringSSLConfig;
    /// use boring::ssl::{SslAcceptor, SslMethod};
    /// use std::convert::TryFrom;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut tls_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
    ///         .unwrap();
    ///     // Set configurations like set_certificate_chain_file or
    ///     // set_private_key_file.
    ///     // let tls_builder.set_ ... ;

    ///     let _config = BoringSSLConfig::try_from(tls_builder);
    /// }
    /// ```
    fn try_from(tls_builder: SslAcceptorBuilder) -> Result<Self, Self::Error> {
        // Any other checks?
        tls_builder.check_private_key()?;

        let acceptor = Arc::new(tls_builder.build());

        Ok(BoringSSLConfig { acceptor })
    }
}

impl fmt::Debug for BoringSSLConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoringSSLConfig").finish()
    }
}

fn default_acceptor_builder() -> Result<SslAcceptorBuilder, BoringSSLError> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    builder.set_alpn_select_callback(|_, client| {
        ssl::select_next_proto(b"\x02h2\x08http/1.1", client).ok_or(ssl::AlpnError::ALERT_FATAL)
    });
    builder.set_options(SslOptions::ALL);
    builder.set_min_proto_version(Some(SslVersion::TLS1))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_permute_extensions(true);
    Ok(builder)
}
