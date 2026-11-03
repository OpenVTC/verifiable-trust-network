//! HTTPS for in-process test servers.
//!
//! A registered endpoint is always `https://` (`vtn/groups/register`), so networks and
//! inboxes in these tests serve TLS under one test certificate authority. Clients trust it
//! through [`client`], and a network under test through `extra_root_certificates`.

use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::serve::Listener;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

pub struct TestCa {
    /// The authority's certificate, PEM.
    pub ca_pem: String,
    acceptor: TlsAcceptor,
}

/// The one test authority, and a server certificate it issued for `127.0.0.1` and
/// `localhost`.
pub fn ca() -> &'static TestCa {
    static CA: OnceLock<TestCa> = OnceLock::new();
    CA.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![
                    CertificateDer::from(leaf.der().to_vec()),
                    CertificateDer::from(ca_cert.der().to_vec()),
                ],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        TestCa {
            ca_pem: ca_cert.pem(),
            acceptor: TlsAcceptor::from(Arc::new(config)),
        }
    })
}

/// An HTTP client that trusts the test authority.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca().ca_pem.as_bytes()).unwrap())
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap()
}

/// A TCP listener that completes a TLS handshake before handing a connection to axum.
pub struct TlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((stream, addr)) = self.tcp.accept().await else {
                continue;
            };
            // A failed handshake is one bad client, not a reason to stop serving.
            if let Ok(tls) = self.acceptor.accept(stream).await {
                return (tls, addr);
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

/// Bind `127.0.0.1:0` for HTTPS; returns the listener and its `https://` URL.
pub async fn bind() -> (TlsListener, String) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", tcp.local_addr().unwrap());
    (
        TlsListener {
            tcp,
            acceptor: ca().acceptor.clone(),
        },
        url,
    )
}

/// Serve `app` over HTTPS on a fresh port; returns its URL.
pub async fn serve(app: Router) -> String {
    let (listener, url) = bind().await;
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}
