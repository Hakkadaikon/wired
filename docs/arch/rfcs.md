# Implemented Specifications and Why They Matter

QUIC is not complete in a single RFC.
Only when several standards are stacked together — the transport core itself, TLS 1.3 for encryption, the cryptographic primitives beneath it, HTTP/3 spoken above it, and even the IP and UDP that form the foundation — does one connection come together.
Here the implemented specifications are divided into seven groups, showing why each group is needed and what each specification is for.

## QUIC core

QUIC's minimal core splits into three responsibilities: transport, its encryption, and loss recovery.
Onto the body that defines the shape of packets and the connection's state transitions, a layer that ties TLS 1.3 into QUIC's key schedule and a layer that adds the retransmission and congestion control UDP lacks are stacked.
The invariants document gathers the assumptions that span these into one place.

| Spec | Title | Link | Why |
|------|------------|--------|-----------|
| RFC 9000 | QUIC: A UDP-Based Multiplexed and Secure Transport | https://www.rfc-editor.org/rfc/rfc9000 | The body defining the packet and frame formats, streams, and the connection's state transitions. |
| RFC 9001 | Using TLS to Secure QUIC | https://www.rfc-editor.org/rfc/rfc9001 | Ties the TLS 1.3 handshake into QUIC's key derivation and packet protection. |
| RFC 9002 | QUIC Loss Detection and Congestion Control | https://www.rfc-editor.org/rfc/rfc9002 | The rules for the sender to perform, on its own, the loss detection and congestion control UDP lacks. |
| RFC 8999 | Version-Independent Properties of QUIC | https://www.rfc-editor.org/rfc/rfc8999 | Defines the header properties that are fixed regardless of version, forming the basis for version negotiation. |

## QUIC extensions

Where the core alone is not enough for operation, the later extensions fill in.
Requirements such as path reachability checks, observability, new congestion control, longer connection IDs, and active path discovery are all standardized outside the core.
To produce behavior close to real operation, these need to be taken in.

| Spec | Title | Link | Why |
|------|------------|--------|-----------|
| RFC 9221 | An Unreliable Datagram Extension to QUIC | https://www.rfc-editor.org/rfc/rfc9221 | Adds the DATAGRAM frame that gives up reliability to take low latency. |
| RFC 9287 | Greasing the QUIC Bit | https://www.rfc-editor.org/rfc/rfc9287 | Deliberately varies the fixed bit to keep middleboxes from ossifying its value. |
| RFC 9368 | Compatible Version Negotiation for QUIC | https://www.rfc-editor.org/rfc/rfc9368 | Defines the procedure to move to a compatible version without an extra round trip. |
| RFC 9369 | QUIC Version 2 | https://www.rfc-editor.org/rfc/rfc9369 | A second version to avoid version ossification; the salts and labels differ per version. |
| RFC 9308 | Applicability of the QUIC Transport Protocol | https://www.rfc-editor.org/rfc/rfc9308 | Shows how QUIC should be used, with operational assumptions and cautions. |
| RFC 9312 | Manageability of the QUIC Transport Protocol | https://www.rfc-editor.org/rfc/rfc9312 | Defines the boundary between what can and cannot be observed from the path. |
| RFC 8899 | Packetization Layer Path MTU Discovery for Datagram Transport Protocols | https://www.rfc-editor.org/rfc/rfc8899 | Discovers the MTU of a datagram path without relying on ICMP. |

## TLS and PKI

QUIC's packet-protection keys are made by the TLS 1.3 handshake.
Onto the handshake body that performs key exchange and authentication hang the syntax and verification of the certificate that proves the server, the signature algorithms, and the extensions.
Because not even the first byte can be encrypted without keys, this group is the very premise of QUIC.

| Spec | Title | Link | Why |
|------|------------|--------|-----------|
| RFC 8446 | The Transport Layer Security (TLS) Protocol Version 1.3 | https://www.rfc-editor.org/rfc/rfc8446 | The body of the handshake performing key exchange and authentication, and the key schedule. |
| RFC 5280 | Internet X.509 Public Key Infrastructure Certificate and CRL Profile | https://www.rfc-editor.org/rfc/rfc5280 | Defines the certificate syntax and the constraints to honor during verification. |
| RFC 5480 | Elliptic Curve Cryptography Subject Public Key Information | https://www.rfc-editor.org/rfc/rfc5480 | Defines the representation of elliptic-curve public keys in a certificate. |
| RFC 5758 | Internet X.509 PKI: Additional Algorithms and Identifiers for DSA and ECDSA | https://www.rfc-editor.org/rfc/rfc5758 | Maps the ECDSA signature-algorithm identifiers onto certificates. |
| RFC 8410 | Algorithm Identifiers for Ed25519, Ed448, X25519, and X448 | https://www.rfc-editor.org/rfc/rfc8410 | The identifiers for handling Ed25519 and X25519 in certificates and key information. |
| RFC 6066 | Transport Layer Security (TLS) Extensions: Extension Definitions | https://www.rfc-editor.org/rfc/rfc6066 | Defines the basics of TLS extensions such as SNI; needed to convey the target host name. |
| RFC 6125 | Representation and Verification of Domain-Based Application Service Identity | https://www.rfc-editor.org/rfc/rfc6125 | Defines the rules for matching the certificate name against the target host name. |
| RFC 7301 | Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension | https://www.rfc-editor.org/rfc/rfc7301 | Selects HTTP/3 during the handshake via ALPN. |
| RFC 8017 | PKCS #1: RSA Cryptography Specifications Version 2.2 | https://www.rfc-editor.org/rfc/rfc8017 | Defines the RSA signature and RSASSA-PSS verification procedure; needed to verify RSA certificates. |

## Cryptographic primitives

The TLS and QUIC key schedules are built by combining lower-level cryptographic functions.
The AEAD that protects packets, the HKDF that derives keys, the signatures that authenticate the peer, and the hashes and elliptic curves that underpin them gather here.
These are pure functions that know nothing of QUIC and can be verified on their own with official test vectors.

| Spec | Title | Link | Why |
|------|------------|--------|-----------|
| RFC 8439 | ChaCha20 and Poly1305 for IETF Protocols | https://www.rfc-editor.org/rfc/rfc8439 | An AEAD cipher usable even in environments without AES. |
| FIPS 197 | Advanced Encryption Standard (AES) | https://csrc.nist.gov/pubs/fips/197/final | The body of the AES block cipher; the foundation of AES-GCM. |
| SP 800-38D | Recommendation for Block Cipher Modes of Operation: GCM and GMAC | https://csrc.nist.gov/pubs/sp/800/38/d/final | The GCM mode that turns AES into an AEAD; the default packet-protection scheme. |
| RFC 7748 | Elliptic Curves for Security | https://www.rfc-editor.org/rfc/rfc7748 | Defines the curve arithmetic for X25519 key exchange; creates the ECDHE shared secret. |
| RFC 8032 | Edwards-Curve Digital Signature Algorithm (EdDSA) | https://www.rfc-editor.org/rfc/rfc8032 | The Ed25519 signature-verification procedure; needed to verify certificate signatures. |
| RFC 6979 | Deterministic Usage of DSA and ECDSA | https://www.rfc-editor.org/rfc/rfc6979 | Derives the ECDSA nonce deterministically, avoiding accidents in the randomness source. |
| RFC 6090 | Fundamental Elliptic Curve Cryptography Algorithms | https://www.rfc-editor.org/rfc/rfc6090 | Defines the basic operations on elliptic curves; the foundation of the P-256 implementation. |
| FIPS 186-4 | Digital Signature Standard (DSS) | https://csrc.nist.gov/pubs/fips/186/4/final | The rules and curve parameters for ECDSA P-256 signature verification. |
| FIPS 180-4 | Secure Hash Standard (SHS) | https://csrc.nist.gov/pubs/fips/180/4/final | SHA-256 and SHA-512; the foundation of the handshake transcript and key derivation. |
| FIPS 198-1 | The Keyed-Hash Message Authentication Code (HMAC) | https://csrc.nist.gov/pubs/fips/198/1/final | HMAC; the foundation of HKDF and Finished verification. |
| RFC 5869 | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | https://www.rfc-editor.org/rfc/rfc5869 | The key-derivation function that drives the whole TLS 1.3 key schedule. |

## HTTP/3 and QPACK

Speaking HTTP over QUIC needs a layer that remaps HTTP's semantics onto QUIC's streams.
Header compression cannot use HTTP/2's HPACK as is.
Because QUIC's streams arrive independently of each other, HPACK, which depends on ordering, brings back head-of-line blocking at the start of a header block.
QPACK splits the encoder and decoder instructions onto separate streams and synchronizes with the Required Insert Count to avoid this.

| Spec | Title | Link | Why |
|------|------------|--------|-----------|
| RFC 9114 | HTTP/3 | https://www.rfc-editor.org/rfc/rfc9114 | The body mapping HTTP's semantics onto frames over QUIC streams. |
| RFC 9110 | HTTP Semantics | https://www.rfc-editor.org/rfc/rfc9110 | The version-independent HTTP semantics such as methods, status, and headers. |
| RFC 9204 | QPACK: Field Compression for HTTP/3 | https://www.rfc-editor.org/rfc/rfc9204 | Header compression that avoids head-of-line blocking under stream independence. |
| RFC 7541 | HPACK: Header Compression for HTTP/2 | https://www.rfc-editor.org/rfc/rfc7541 | Defines the static table, Huffman code, and integer encoding that QPACK reuses. |
| RFC 9218 | Extensible Prioritization Scheme for HTTP | https://www.rfc-editor.org/rfc/rfc9218 | Defines the mechanism for conveying request priorities. |

## WebTransport

HTTP/3 carries requests and responses, but an application that wants raw bidirectional streams and datagrams between a browser and a server needs one more layer.
WebTransport overlays such a session on top of an HTTP/3 connection: an Extended CONNECT request establishes the session, and the streams and DATAGRAMs bound to it become the application's transport.
This SDK implements the server side — the session state machine, the WebTransport capsules, and the error-code mapping under `src/app/webtransport/` — and `examples/webtransport_chat` drives a live session from a real browser.

| Spec | Title | Link | Why |
|------|------------|--------|-----------|
| draft-ietf-webtrans-http3 | WebTransport over HTTP/3 | https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3 | The body of the protocol: the session state machine, the WebTransport stream signals, the session-close capsules, and the application error-code mapping; implemented against draft-15. |
| RFC 9220 | Bootstrapping WebSockets with HTTP/3 | https://www.rfc-editor.org/rfc/rfc9220 | Brings Extended CONNECT into HTTP/3; the `:protocol` pseudo-header and SETTINGS_ENABLE_CONNECT_PROTOCOL that session establishment rides on. |
| RFC 9297 | HTTP Datagrams and the Capsule Protocol | https://www.rfc-editor.org/rfc/rfc9297 | Binds DATAGRAMs to a request stream via SETTINGS_H3_DATAGRAM and defines the generic capsule envelope the WebTransport capsules are layered on. |

## Lower-layer protocols

QUIC's packets are ultimately carried as IP datagrams on top of UDP.
Because this SDK does not rely on the kernel's IP / UDP stack and in places assembles the IPv4 header, the UDP header, and even the checksum itself, these foundations also fall within the scope of implementation.

| Spec | Title | Link | Why |
|------|------------|--------|-----------|
| RFC 768 | User Datagram Protocol | https://www.rfc-editor.org/rfc/rfc768 | The UDP header format and checksum that QUIC rides on. |
| RFC 791 | Internet Protocol | https://www.rfc-editor.org/rfc/rfc791 | The IPv4 header format that carries the UDP datagram. |
| RFC 1071 | Computing the Internet Checksum | https://www.rfc-editor.org/rfc/rfc1071 | The checksum-computation procedure for IP and UDP. |

---

**Next:** how the layers implement these specs →
[The Layers](layers.md) · security properties the implementation enforces →
[Security](../security.md) · all pages → [documentation index](../README.md)
