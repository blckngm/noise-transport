Simple secure async stream IO with `noise_protocol`.

# Example

```rust
use noise_transport::*;
use noise_rust_crypto::*;
use noise_protocol::DH;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
    // Generate or load static X25519 key.
    let s1 = <X25519 as DH>::genkey();
    let s2 = <X25519 as DH>::genkey();
    let s1_pk = <X25519 as DH>::pubkey(&s1);
    let s2_pk = <X25519 as DH>::pubkey(&s2);

    let (stream1, stream2) = tokio::net::UnixStream::pair().unwrap();
    // Handshake.
    let (result1, result2) = tokio::try_join!(
        // An extra handshake message can be sent.
        handshake_initiate::<_, X25519, ChaCha20Poly1305, Sha256>(stream1, s1, b"hello"),
        handshake_respond::<_, X25519, ChaCha20Poly1305, Sha256>(stream2, s2, b"hi"),
    )
    .unwrap();
    assert_eq!(result1.hs().get_rs().unwrap(), s2_pk);
    assert_eq!(result2.hs().get_rs().unwrap(), s1_pk);
    assert_eq!(result1.hs().get_hash(), result2.hs().get_hash());
    assert_eq!(result1.received_message(), b"hi");
    assert_eq!(result2.received_message(), b"hello");

    let mut s1 = result1.wrapped_stream();
    let mut s2 = result2.wrapped_stream();

    let write = async move {
        for _ in 0..100 {
            s1.write_all(&[0u8; 65535 + 7]).await.unwrap();
        }
        s1.flush().await.unwrap();
    };
    let read = async move {
        let mut buf = [1u8; 65535 + 7];
        for _ in 0..100 {
            s2.read_exact(&mut buf).await.unwrap();
        }
    };
    tokio::join!(write, read);
}
```

# Application Responsibility

- [Channel Binding](http://www.noiseprotocol.org/noise.html#channel-binding)

- [Session Termination](http://www.noiseprotocol.org/noise.html#application-responsibilities)
