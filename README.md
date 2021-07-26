# A low-level X.509 parsing and certificate signature verification library.

barebones-x509 can verify the signatures of X.509 certificates, as well as certificates made by
their private keys.  It can also verify that a certificate is valid for the given time.
However, it is (by design) very low-level: it does not know about *any* X.509 extensions, and
does not parse distinguished names at all.  It also provides no path-building facilities.  As
such, it is not intended for use with the web PKI; use webpki for that.

barebones-x509’s flexibiity is a double-edged sword: it allows it to be used in situations
where webpki cannot be used, but it also makes it significantly more dangerous.  As a general
rule, barebones-x509 will accept any certificate that webpki will, but it will also accept
certificates that webpki will reject.  If you find a certificate that barebones-x509 rejects
and webpki rejects, please report it as a bug.

barebones-x509 was developed for use with
[libp2p](https://github.com/libp2p), which uses certificates that webpki
cannot handle.  Its bare-bones design ensures that it can handle almost any conforming X.509
certificate, but it also means that the application is responsible for ensuring that the
certificate has valid X.509 extensions.  barebones-x509 cannot distinguish between a
certificate valid for `mozilla.org` and one for `evilmalware.com`!  However, barebones-x509
does provide the hooks needed for higher-level libraries to be built on top of it.

Like webpki, barebones-x509 is zero-copy and `#![no_std]` friendly.  If built without the
`alloc` feature, barebones-x509 will not rely on features of *ring* that require heap
allocation, specifically RSA.  barebones-x509 should never panic on any input.
 
# License

barebones-x509 is dual-licensed under the [MIT license](LICENSE-MIT) and the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
