use super::Stream;
use futures_util::future::poll_fn;
use futures_util::task::noop_waker_ref;
use rustls::{
    Certificate, ClientConfig, ClientConnection, Connection, NoClientAuth, PrivateKey,
    RootCertStore, ServerConfig, ServerConnection, ServerName,
};
use rustls_pemfile::{certs, rsa_private_keys};
use std::convert::TryFrom;
use std::io::{self, BufReader, Cursor, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use webpki::DNSNameRef;

struct Good<'a>(&'a mut dyn Connection);

impl<'a> AsyncRead for Good<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut buf2 = buf.initialize_unfilled();

        Poll::Ready(match self.0.write_tls(buf2.by_ref()) {
            Ok(n) => {
                buf.advance(n);
                Ok(())
            }
            Err(err) => Err(err),
        })
    }
}

impl<'a> AsyncWrite for Good<'a> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let len = self.0.read_tls(buf.by_ref())?;
        self.0
            .process_new_packets()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0
            .process_new_packets()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.send_close_notify();
        Poll::Ready(Ok(()))
    }
}

struct Pending;

impl AsyncRead for Pending {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Pending {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Eof;

impl AsyncRead for Eof {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Eof {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn stream_good() -> io::Result<()> {
    const FILE: &'static [u8] = include_bytes!("../../README.md");

    let (mut server, mut client) = make_pair();
    poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;
    println!("before copy");
    io::copy(&mut Cursor::new(FILE), &mut server.writer())?;
    println!("after copy");

    {
        let mut good = Good(&mut server);
        let mut stream = Stream::new(&mut good, &mut client);

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        println!("after read_to_end");
        assert_eq!(buf, FILE);
        stream.write_all(b"Hello World!").await?;
        println!("after write all");
        stream.flush().await?;
        println!("after flush");
    }

    let mut buf = String::new();
    server.reader().read_to_string(&mut buf)?;
    println!("after read_to_string");
    assert_eq!(buf, "Hello World!");

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_bad() -> io::Result<()> {
    let (mut server, mut client) = make_pair();
    poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;
    client.set_buffer_limit(Some(1024));

    let mut bad = Pending;
    let mut stream = Stream::new(&mut bad, &mut client);
    assert_eq!(
        poll_fn(|cx| stream.as_mut_pin().poll_write(cx, &[0x42; 8])).await?,
        8
    );
    assert_eq!(
        poll_fn(|cx| stream.as_mut_pin().poll_write(cx, &[0x42; 8])).await?,
        8
    );
    let r = poll_fn(|cx| stream.as_mut_pin().poll_write(cx, &[0x00; 1024])).await?; // fill buffer
    assert!(r < 1024);

    let mut cx = Context::from_waker(noop_waker_ref());
    let ret = stream.as_mut_pin().poll_write(&mut cx, &[0x01]);
    assert!(ret.is_pending());

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_handshake() -> io::Result<()> {
    let (mut server, mut client) = make_pair();

    {
        let mut good = Good(&mut server);
        let mut stream = Stream::new(&mut good, &mut client);
        let (r, w) = poll_fn(|cx| stream.handshake(cx)).await?;

        assert!(r > 0);
        assert!(w > 0);

        poll_fn(|cx| stream.handshake(cx)).await?; // finish server handshake
    }

    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_handshake_eof() -> io::Result<()> {
    let (_, mut client) = make_pair();

    let mut bad = Eof;
    let mut stream = Stream::new(&mut bad, &mut client);

    let mut cx = Context::from_waker(noop_waker_ref());
    let r = stream.handshake(&mut cx);
    assert_eq!(
        r.map_err(|err| err.kind()),
        Poll::Ready(Err(io::ErrorKind::UnexpectedEof))
    );

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_eof() -> io::Result<()> {
    let (mut server, mut client) = make_pair();
    poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;

    let mut good = Good(&mut server);
    let mut stream = Stream::new(&mut good, &mut client).set_eof(true);

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    assert_eq!(buf.len(), 0);

    Ok(()) as io::Result<()>
}

fn make_pair() -> (ServerConnection, ClientConnection) {
    const CERT: &str = include_str!("../../tests/end.cert");
    const CHAIN: &str = include_str!("../../tests/end.chain");
    const RSA: &str = include_str!("../../tests/end.rsa");

    let cert = certs(&mut BufReader::new(Cursor::new(CERT)))
        .map(|v| v.into_iter().map(|der| Certificate(der)).collect())
        .unwrap();
    let mut keys: Vec<PrivateKey> = rsa_private_keys(&mut BufReader::new(Cursor::new(RSA)))
        .map(|v| v.into_iter().map(|der| PrivateKey(der)).collect())
        .unwrap();
    let sconfig_builder = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap();
    let sconfig = sconfig_builder
        .with_no_client_auth()
        .with_single_cert(cert, keys.pop().unwrap())
        .unwrap();
    let server = ServerConnection::new(Arc::new(sconfig)).unwrap();

    let cconfig_builder = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap();

    let mut root_store = RootCertStore::empty();
    let chain = certs(&mut BufReader::new(Cursor::new(CHAIN))).unwrap();
    root_store.add_parsable_certificates(&chain);

    let cconfig = cconfig_builder
        .with_root_certificates(root_store, &[])
        .with_no_client_auth();
    let client = ClientConnection::new(
        Arc::new(cconfig),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();

    (server, client)
}

fn do_handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    let mut good = Good(server);
    let mut stream = Stream::new(&mut good, client);

    while stream.connection.is_handshaking() {
        ready!(stream.handshake(cx))?;
    }

    while stream.connection.wants_write() {
        ready!(stream.write_io(cx))?;
    }

    Poll::Ready(Ok(()))
}
