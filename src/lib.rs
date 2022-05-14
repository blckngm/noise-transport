#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures_core::{ready, Stream};
use noise_protocol::{
    patterns::noise_xx, Cipher, CipherState, HandshakeState, HandshakeStateBuilder, Hash, DH,
};
use pin_project_lite::pin_project;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

/// Handshake error.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum HandshakeError {
    /// IO error.
    #[error("io error {0}")]
    Io(#[from] io::Error),
    /// Noise handshake error.
    #[error("noise error {0}")]
    Noise(#[from] noise_protocol::Error),
    /// The message specified is too large to be encoded.
    #[error("message too large")]
    MessageTooLarge,
}

/// Handshake result returned by `handshake_initiate` or `handshake_respond`.
pub struct HandshakeResult<S, D: DH, C: Cipher, H: Hash> {
    stream: S,
    hs: HandshakeState<D, C, H>,
    received_message: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite, D: DH, C: Cipher, H: Hash> HandshakeResult<S, D, C, H> {
    /// Create a new `HandshakeResult`.
    pub fn new(stream: S, hs: HandshakeState<D, C, H>, received_message: Vec<u8>) -> Self {
        Self {
            stream,
            hs,
            received_message,
        }
    }

    /// Get the underlying IO stream.
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Get the `HandshakeState`.
    ///
    /// You can use this to get the other party's static public key, the
    /// handshake hash etc.
    pub fn hs(&self) -> &HandshakeState<D, C, H> {
        &self.hs
    }

    /// Get the extra handshake message the other party sends.
    pub fn received_message(&self) -> &[u8] {
        &self.received_message
    }

    /// Get a mutable reference to the extra handshake message the other party
    /// sends.
    pub fn received_message_mut(&mut self) -> &mut Vec<u8> {
        &mut self.received_message
    }

    /// Get write and read cipher states.
    ///
    /// # Example
    ///
    /// Working with split IO streams:
    ///
    /// ```no_run
    /// # use noise_transport::*;
    /// # use noise_rust_crypto::*;
    /// # use tokio::net::TcpStream;
    /// # let result: HandshakeResult<TcpStream, X25519, ChaCha20Poly1305, Sha256> = None.unwrap();
    /// let (cw, cr) = result.write_read_cipher_states();
    /// // https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html#method.into_split
    /// let (r, w) = result.into_inner().into_split();
    /// let w = WriteStream::new(w, cw);
    /// let r = ReadStream::new(r, cr);
    /// ```
    pub fn write_read_cipher_states(&self) -> (CipherState<C>, CipherState<C>) {
        let (initiator_to_responder, responder_to_initiator) = self.hs.get_ciphers();
        if self.hs.get_is_initiator() {
            (initiator_to_responder, responder_to_initiator)
        } else {
            (responder_to_initiator, initiator_to_responder)
        }
    }

    /// Get the IO stream wrapped in `ReadStream` and `WriteStream`.
    ///
    /// Reading and writing on the returned stream will be secure, i.e.
    /// encrypted and authenticated by keys derived from the handshake result.
    pub fn wrapped_stream(self) -> WriteStream<ReadStream<S, C>, C> {
        let (w, r) = self.write_read_cipher_states();
        WriteStream::new(ReadStream::new(self.stream, r), w)
    }
}

/// Handshake as initiator on an async IO stream.
///
/// The `Noise_XX` pattern is used:
///
/// ```text
/// XX:
///     -> e
///     <- e, ee, s, es
///     -> s, se
/// ```
///
/// The first message is always 32-byte long.
///
/// The second and third messages are variable length. The message length is
/// written first in big-endian 16-bit unsigned integer format.
///
/// The second message would contain the other party's extra handshake message.
///
/// The third message contains our extra handshake message.
///
/// Extra handshake messages are encrypted with strong forward secrecy.
///
/// Note that we haven't authenticate the other party when sending the extra
/// handshake message. So the message might be sent to any party, including an
/// active attacker.
pub async fn handshake_initiate<S: AsyncRead + AsyncWrite + Unpin, D: DH, C: Cipher, H: Hash>(
    mut stream: S,
    our_static_private_key: <D as DH>::Key,
    message: &[u8],
) -> Result<HandshakeResult<S, D, C, H>, HandshakeError> {
    let mut hs: HandshakeState<D, C, H> = {
        let mut builder = HandshakeStateBuilder::new();
        builder
            .set_is_initiator(true)
            .set_pattern(noise_xx())
            .set_prologue(b"nosie-transport v0")
            .set_s(our_static_private_key);
        builder.build_handshake_state()
    };
    let mut buf = [0u8; 32];
    // Additional message can be written here. It will NOT be encrypted, but will be authenticated.
    hs.write_message(&[], &mut buf)?;
    stream.write_all(&buf).await?;
    stream.flush().await?;

    let mut len_bytes = [0u8; 2];
    stream.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes);
    let mut buf = vec![0u8; len.into()];
    stream.read_exact(&mut buf).await?;
    let received_message = hs.read_message_vec(&buf)?;

    let buf = hs.write_message_vec(message)?;
    let len: u16 = buf
        .len()
        .try_into()
        .map_err(|_| HandshakeError::MessageTooLarge)?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&buf).await?;
    stream.flush().await?;

    Ok(HandshakeResult::new(stream, hs, received_message))
}

/// Handshake as responder on an async IO stream.
///
/// The `Noise_XX` pattern is used:
///
/// ```text
/// XX:
///     -> e
///     <- e, ee, s, es
///     -> s, se
/// ```
///
/// The first message is always 32-byte long.
///
/// The second and third messages are variable length. The message length is
/// written first in big-endian 16-bit unsigned integer format.
///
/// The second message contains our extra handshake message.
///
/// The third message should contain the other party's extra handshake message.
///
/// Extra handshake messages are encrypted with strong forward secrecy.
///
/// Note that we haven't authenticate the other party when sending the extra
/// handshake message. So the message might be sent to any party, including an
/// active attacker.
pub async fn handshake_respond<S: AsyncRead + AsyncWrite + Unpin, D: DH, C: Cipher, H: Hash>(
    mut stream: S,
    our_static_private_key: <D as DH>::Key,
    message: &[u8],
) -> Result<HandshakeResult<S, D, C, H>, HandshakeError> {
    let mut hs: HandshakeState<D, C, H> = {
        let mut builder = HandshakeStateBuilder::new();
        builder
            .set_is_initiator(false)
            .set_pattern(noise_xx())
            .set_prologue(b"nosie-transport v0")
            .set_s(our_static_private_key);
        builder.build_handshake_state()
    };
    let mut buf = [0u8; 32];
    stream.read_exact(&mut buf).await?;
    hs.read_message(&buf, &mut [])?;

    // Message written here will be encrypted to peer's ephemeral key.
    let buf = hs.write_message_vec(message)?;
    let len: u16 = buf
        .len()
        .try_into()
        .map_err(|_| HandshakeError::MessageTooLarge)?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&buf).await?;
    stream.flush().await?;

    let mut len_bytes = [0u8; 2];
    stream.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes);
    let mut buf = vec![0u8; len.into()];
    stream.read_exact(&mut buf).await?;
    let received_message = hs.read_message_vec(&buf)?;

    Ok(HandshakeResult::new(stream, hs, received_message))
}

// Largely based on tokio BufWriter.
pin_project! {
    /// Wraps another stream, encrypt and authenticate frames when writing.
    ///
    /// Each chunk of data written is AEAD encrypted, and prefixed by its length, in big-endian 16-bit unsigned integer format.
    pub struct WriteStream<W, C: Cipher> {
        #[pin]
        inner: W,
        buf: Vec<u8>,
        written: usize,
        state: CipherState<C>,
    }
}

impl<W: AsyncWrite, C: Cipher> WriteStream<W, C> {
    /// Create a new `WriteStream`.
    pub fn new(stream: W, state: CipherState<C>) -> Self {
        let mut buf = vec![0u8; 2 + MAX_PLAINTEXT_LEN + 16];
        buf.clear();
        Self {
            inner: stream,
            buf,
            written: 0,
            state,
        }
    }

    fn flush_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut me = self.project();

        let len = me.buf.len();
        let mut ret = Ok(());
        while *me.written < len {
            match ready!(me.inner.as_mut().poll_write(cx, &me.buf[*me.written..])) {
                Ok(0) => {
                    ret = Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write the buffered data",
                    ));
                    break;
                }
                Ok(n) => *me.written += n,
                Err(e) => {
                    ret = Err(e);
                    break;
                }
            }
        }
        if *me.written > 0 {
            me.buf.drain(..*me.written);
        }
        *me.written = 0;
        Poll::Ready(ret)
    }

    /// Get a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Get a mutable reference to the underlying writer.
    ///
    /// It is inadvisable to directly write to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Get a pinned mutable reference to the underlying writer.
    ///
    /// It is inadvisable to directly write to the underlying writer.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut W> {
        self.project().inner
    }

    /// Consume this `WriteStream`, returning the underlying writer.
    ///
    /// Note that any leftover data in the internal buffer is lost.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

// Noise spec says that maximum noise message length is 65535. That includes the length of the authentication tag.
const MAX_PLAINTEXT_LEN: usize = (u16::MAX - 16) as usize;

impl<W: AsyncWrite, C: Cipher> AsyncWrite for WriteStream<W, C> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if !self.buf.is_empty() {
            ready!(self.as_mut().flush_buf(cx))?;
        }

        let me = self.as_mut().project();

        buf = &buf[..std::cmp::min(MAX_PLAINTEXT_LEN, buf.len())];

        me.buf.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        unsafe {
            me.buf.set_len(2 + buf.len() + 16);
        }
        me.state.encrypt(buf, &mut me.buf[2..]);

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        ready!(self.as_mut().flush_buf(cx))?;
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        ready!(self.as_mut().flush_buf(cx))?;
        self.project().inner.poll_shutdown(cx)
    }
}

impl<W: AsyncRead, C: Cipher> AsyncRead for WriteStream<W, C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

pin_project! {
    /// Wraps another read stream, decrypt and verify frames when reading.
    pub struct ReadStream<R, C: Cipher> {
        #[pin]
        framed: FramedRead<R, LengthDelimitedCodec>,
        plaintext_buf: Vec<u8>,
        read: usize,
        state: CipherState<C>,
    }
}

impl<R: AsyncRead, C: Cipher> ReadStream<R, C> {
    /// Create a new `ReadStream`.
    pub fn new(stream: R, state: CipherState<C>) -> Self {
        let mut plaintext_buf = vec![0u8; MAX_PLAINTEXT_LEN];
        plaintext_buf.clear();
        Self {
            framed: LengthDelimitedCodec::builder()
                .length_field_type::<u16>()
                .length_adjustment(16)
                .new_read(stream),
            plaintext_buf,
            read: 0,
            state,
        }
    }

    /// Get a reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        self.framed.get_ref()
    }

    /// Get a mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        self.framed.get_mut()
    }

    /// Get a pinned mutable reference to the underlying reader.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut R> {
        self.project().framed.get_pin_mut()
    }

    /// Consumes this WriteStream, returning the underlying reader.
    ///
    /// Note that any leftover data in the internal buffer is lost.
    pub fn into_inner(self) -> R {
        self.framed.into_inner()
    }
}

impl<R: AsyncRead, C: Cipher> AsyncRead for ReadStream<R, C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.project();

        if me.plaintext_buf.is_empty() {
            let ciphertext_and_tag = match ready!(me.framed.poll_next(cx)) {
                Some(buf) => buf?,
                None => return Poll::Ready(Ok(())),
            };

            unsafe {
                me.plaintext_buf.set_len(
                    ciphertext_and_tag
                        .len()
                        .checked_sub(16)
                        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "frame too short"))?,
                );
            }

            me.state
                .decrypt(&ciphertext_and_tag, &mut me.plaintext_buf[..])
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "decryption failed"))?;
        }

        let len = std::cmp::min(buf.remaining(), me.plaintext_buf.len() - *me.read);
        if len > 0 {
            buf.put_slice(&me.plaintext_buf[*me.read..*me.read + len]);
            *me.read += len;
            if *me.read == me.plaintext_buf.len() {
                me.plaintext_buf.clear();
                *me.read = 0;
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<R: AsyncWrite, C: Cipher> AsyncWrite for ReadStream<R, C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().framed.get_pin_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().framed.get_pin_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().framed.get_pin_mut().poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use noise_protocol::CipherState;
    use noise_rust_crypto::ChaCha20Poly1305;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{ReadStream, WriteStream};

    #[tokio::test]
    async fn test_write_flush_and_read() {
        let mut w = WriteStream::new(
            Vec::new(),
            CipherState::<ChaCha20Poly1305>::new(&[7; 32], 0),
        );
        assert_eq!(w.write(&[1u8; 32]).await.unwrap(), 32);
        assert_eq!(w.write(&[2u8; 32]).await.unwrap(), 32);
        w.write_all(&[3u8; 65535]).await.unwrap();
        w.flush().await.unwrap();

        let result = w.into_inner();

        let mut r = ReadStream::new(
            Cursor::new(result),
            CipherState::<ChaCha20Poly1305>::new(&[7; 32], 0),
        );
        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 16 + 32 + 65535];
        r.read_exact(&mut buf1).await.unwrap();
        r.read_exact(&mut buf2).await.unwrap();
        assert_eq!(buf1, [1u8; 16]);
        assert!(buf2[..16].iter().any(|x| *x == 1));
        assert!(buf2[16..32].iter().any(|x| *x == 2));
        assert!(buf2[32..].iter().any(|x| *x == 3));
        assert_eq!(r.read(&mut buf1).await.unwrap(), 0);
    }
}
