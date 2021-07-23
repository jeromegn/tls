use futures_util::future::TryFutureExt;
use lazy_static::lazy_static;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, rsa_private_keys};
use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::{io, thread};
use tokio::io::{copy, split, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const CERT: &str = include_str!("end.cert");
const CHAIN: &str = include_str!("end.chain");
const RSA: &str = include_str!("end.rsa");

lazy_static! {
    static ref TEST_SERVER: (SocketAddr, &'static str, &'static str) = {
        let cert = certs(&mut BufReader::new(Cursor::new(CERT)))
            .map(|v| v.into_iter().map(|der| Certificate(der)).collect())
            .unwrap();
        let mut keys: Vec<PrivateKey> = rsa_private_keys(&mut BufReader::new(Cursor::new(RSA)))
            .map(|v| v.into_iter().map(|der| PrivateKey(der)).collect())
            .unwrap();

        let config_builder = ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap();

        let config = config_builder
            .with_no_client_auth()
            .with_single_cert(cert, keys.pop().unwrap())
            .unwrap();

        let acceptor = TlsAcceptor::from(Arc::new(config));

        let (send, recv) = channel();

        thread::spawn(move || {
            let runtime = runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .unwrap();
            let runtime = Arc::new(runtime);
            let runtime2 = runtime.clone();

            let done = async move {
                let addr = SocketAddr::from(([127, 0, 0, 1], 0));
                let listener = TcpListener::bind(&addr).await?;

                send.send(listener.local_addr()?).unwrap();

                loop {
                    let (stream, _) = listener.accept().await?;

                    let acceptor = acceptor.clone();
                    let fut = async move {
                        let stream = acceptor.accept(stream).await?;

                        let (mut reader, mut writer) = split(stream);
                        copy(&mut reader, &mut writer).await?;

                        Ok(()) as io::Result<()>
                    }
                    .unwrap_or_else(|err| eprintln!("server: {:?}", err));

                    runtime2.spawn(fut);
                }
            }
            .unwrap_or_else(|err: io::Error| eprintln!("server: {:?}", err));

            runtime.block_on(done);
        });

        let addr = recv.recv().unwrap();
        (addr, "testserver.com", CHAIN)
    };
}

fn start_server() -> &'static (SocketAddr, &'static str, &'static str) {
    &*TEST_SERVER
}

async fn start_client(addr: SocketAddr, domain: &str, config: Arc<ClientConfig>) -> io::Result<()> {
    const FILE: &'static [u8] = include_bytes!("../README.md");

    let config = TlsConnector::from(config);
    let mut buf = vec![0; FILE.len()];

    let stream = TcpStream::connect(&addr).await?;
    let mut stream = config.connect(domain, stream).await?;
    stream.write_all(FILE).await?;
    stream.flush().await?;
    stream.read_exact(&mut buf).await?;

    assert_eq!(buf, FILE);

    Ok(())
}

#[tokio::test]
async fn pass() -> io::Result<()> {
    let (addr, domain, chain) = start_server();

    // TODO: not sure how to resolve this right now but since
    // TcpStream::bind now returns a future it creates a race
    // condition until its ready sometimes.
    use std::time::*;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let config_builder = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap();

    let mut root_store = RootCertStore::empty();
    let chain = certs(&mut BufReader::new(Cursor::new(chain))).unwrap();
    root_store.add_parsable_certificates(&chain);

    let config = Arc::new(
        config_builder
            .with_root_certificates(root_store, &[])
            .with_no_client_auth(),
    );

    start_client(addr.clone(), domain, config.clone()).await?;

    Ok(())
}

#[tokio::test]
async fn fail() -> io::Result<()> {
    let (addr, domain, chain) = start_server();

    let config_builder = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap();

    let mut root_store = RootCertStore::empty();
    let chain = certs(&mut BufReader::new(Cursor::new(chain))).unwrap();
    root_store.add_parsable_certificates(&chain);

    let config = Arc::new(
        config_builder
            .with_root_certificates(root_store, &[])
            .with_no_client_auth(),
    );

    assert_ne!(domain, &"google.com");
    let ret = start_client(addr.clone(), "google.com", config).await;
    assert!(ret.is_err());

    Ok(())
}
