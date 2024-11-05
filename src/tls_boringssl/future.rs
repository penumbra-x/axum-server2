//! Future types.

use super::BoringSSLConfig;
use futures_util::future::BoxFuture;
use pin_project_lite::pin_project;
use std::io::{Error, ErrorKind};
use std::time::Duration;
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{timeout, Timeout};

use boring::ssl::Ssl;
use tokio_boring::{HandshakeError, SslStream, SslStreamBuilder};

pin_project! {
    /// Future type for [`BoringSSLSSLAcceptor`](crate::tls_boringssl::BoringSSSslAcceptor).
    pub struct BoringSSLSSLAcceptorFuture<F, I, S> {
        #[pin]
        inner: AcceptFuture<F, I, S>,
        config: Option<BoringSSLConfig>,
    }
}

impl<F, I, S> BoringSSLSSLAcceptorFuture<F, I, S> {
    pub(crate) fn new(future: F, config: BoringSSLConfig, handshake_timeout: Duration) -> Self {
        let inner = AcceptFuture::InnerAccepting {
            future,
            handshake_timeout,
        };
        let config = Some(config);

        Self { inner, config }
    }
}

impl<F, I, S> fmt::Debug for BoringSSLSSLAcceptorFuture<F, I, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoringSSLSSLAcceptorFuture").finish()
    }
}

pin_project! {
    #[project = AcceptFutureProj]
    enum AcceptFuture<F, I, S> {
        // We are waiting on the inner (lower) future to complete accept()
        // so that we can begin installing TLS into the channel.
        InnerAccepting {
            #[pin]
            future: F,
            handshake_timeout: Duration,
        },
        // We are waiting for TLS to install into the channel so that we can
        // proceed to return the SslStream.
        TlsAccepting {
            #[pin]
            future: Timeout<BoxFuture<'static, Result<SslStream<I>, HandshakeError<I>>>>,
            service: Option<S>,
        }
    }
}

impl<F, I, S> Future for BoringSSLSSLAcceptorFuture<F, I, S>
where
    F: Future<Output = io::Result<(I, S)>>,
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = io::Result<(SslStream<I>, S)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        // The inner future here is what is doing the lower level accept, such as
        // our tcp socket.
        //
        // So we poll on that first, when it's ready we then swap our the inner future to
        // one waiting for our ssl layer to accept/install.
        //
        // Then once that's ready we can then wrap and provide the SslStream back out.

        // This loop exists to allow the Poll::Ready from InnerAccept on complete
        // to re-poll immediately. Otherwise all other paths are immediate returns.
        loop {
            match this.inner.as_mut().project() {
                AcceptFutureProj::InnerAccepting {
                    future,
                    handshake_timeout,
                } => match future.poll(cx) {
                    Poll::Ready(Ok((stream, service))) => {
                        let server_config = this.config.take().expect(
                            "config is not set. this is a bug in axum-server2, please report",
                        );

                        // Change to poll::ready(err)
                        let ssl = match Ssl::new_from_ref(server_config.acceptor.context()) {
                            Ok(ssl) => ssl,
                            Err(e) => {
                                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
                            }
                        };

                        let tls_builder = SslStreamBuilder::new(ssl, stream);
                        let accept_future: BoxFuture<'_, Result<SslStream<I>, HandshakeError<I>>> =
                            Box::pin(tls_builder.accept());

                        let service = Some(service);
                        let handshake_timeout = *handshake_timeout;
                        this.inner.set(AcceptFuture::TlsAccepting {
                            future: timeout(handshake_timeout, accept_future),
                            service,
                        });

                        // the loop is now triggered to immediately poll on
                        // ssl stream accept.
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },

                AcceptFutureProj::TlsAccepting { future, service } => match future.poll(cx) {
                    Poll::Ready(Ok(Ok(stream))) => {
                        let service = service.take().expect("future polled after ready");
                        return Poll::Ready(Ok((stream, service)));
                    }
                    Poll::Ready(Ok(Err(e))) => {
                        return Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string())))
                    }
                    Poll::Ready(Err(timeout)) => {
                        return Poll::Ready(Err(Error::new(ErrorKind::TimedOut, timeout)))
                    }
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }
}
