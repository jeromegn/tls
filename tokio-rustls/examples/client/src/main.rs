use argh::FromArgs;
use rustls_pemfile::certs;
use std::fs::File;
use std::io::Read;
use std::io::{self, BufReader};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{copy, split, stdin as tokio_stdin, stdout as tokio_stdout, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{OwnedTrustAnchor, RootCertStore};
use tokio_rustls::{rustls::ClientConfig, TlsConnector};

/// Tokio Rustls client example
#[derive(FromArgs)]
struct Options {
    /// host
    #[argh(positional)]
    host: String,

    /// port
    #[argh(option, short = 'p', default = "443")]
    port: u16,

    /// domain
    #[argh(option, short = 'd')]
    domain: Option<String>,

    /// cafile
    #[argh(option, short = 'c')]
    cafile: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let options: Options = argh::from_env();

    let addr = (options.host.as_str(), options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let domain = options.domain.unwrap_or(options.host);
    let content = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", domain);

    let config_builder = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap();
    let config = if let Some(cafile) = &options.cafile {
        let certs = certs(&mut BufReader::new(File::open(cafile)?))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;

        let mut root_store = RootCertStore::empty();

        let (_valid, invalid) = root_store.add_parsable_certificates(&certs);
        if invalid > 0 {
            panic!("invalid certificate");
        }

        config_builder
            .with_root_certificates(root_store, &[])
            .with_no_client_auth()
    } else {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        config_builder
            .with_root_certificates(root_store, &[])
            .with_no_client_auth()
    };
    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect(&addr).await?;

    let (mut stdin, mut stdout) = (tokio_stdin(), tokio_stdout());

    let mut stream = connector.connect(&domain, stream).await?;
    stream.write_all(content.as_bytes()).await?;

    let (mut reader, mut writer) = split(stream);

    tokio::select! {
        ret = copy(&mut reader, &mut stdout) => {
            ret?;
        },
        ret = copy(&mut stdin, &mut writer) => {
            ret?;
            writer.shutdown().await?
        }
    }

    Ok(())
}
