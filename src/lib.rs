//! # A low-level X.509 parsing and certificate signature verification library.
//!
//! barebones-x509 can verify the signatures of X.509 certificates, as well as
//! certificates made by their private keys.  It can also verify that a
//! certificate is valid for the given time. However, it is (by design) very
//! low-level: it does not know about *any* X.509 extensions, and does not parse
//! distinguished names at all.  It also provides no path-building facilities.
//! As such, it is not intended for use with the web PKI; use webpki for that.
//!
//! barebones-x509’s flexibiity is a double-edged sword: it allows it to be used
//! in situations where webpki cannot be used, but it also makes it
//! significantly more dangerous.  As a general rule, barebones-x509 will accept
//! any certificate that webpki will, but it will also accept certificates that
//! webpki will reject.  If you find a certificate that barebones-x509 rejects
//! and webpki rejects, please report it as a bug.
//!
//! barebones-x509 was developed for use with
//! [libp2p](https://github.com/libp2p), which uses certificates that webpki
//! cannot handle.  Its bare-bones design ensures that it can handle almost any
//! conforming X.509 certificate, but it also means that the application is
//! responsible for ensuring that the certificate has valid X.509 extensions.
//! barebones-x509 cannot distinguish between a certificate valid for
//! `mozilla.org` and one for `evilmalware.com`!  However, barebones-x509
//! does provide the hooks needed for higher-level libraries to be built on top
//! of it.
//!
//! Like webpki, barebones-x509 is zero-copy and `#![no_std]` friendly.  If
//! built without the `alloc` feature, barebones-x509 will not rely on features
//! of *ring* that require heap allocation, specifically RSA.
//!
//! barebones-x509 should never panic on any input, regardless of its
//! configuration options.  If it does panic, it is considered a security
//! vulnerability and will be fixed with the highest priority.
//!
//! ## Features
//!
//! `barebones-x509` is highly configurable by means of compile-time options.
//! Code that is not used by most users is off by default and must be enabled by
//! means of a cargo feature.  This reduces the attack surface of normal builds.
//!
//! The following features are available:
//!
//! - `legacy-certificates`: Allows parsing legacy v1 and v2 certificates. This
//!   is off by default.
//! - `obsolete-unique-ids`: Allows parsing certificates containing the obsolete
//!   `subjectUniqueId` and `issuerUniqueId` fields.  This is off by default.
//!   The `subjectUniqueId` and `issuerUniqueId` fields available as the
//!   `unique_id` field on the [`X509Certificate`] struct.  This feature is made
//!   available so that `barebones-x509` can claim to be able to parse any valid
//!   X.509 certificate.  If you do need to enable it, please e-mail me at
//!   <demiobenour@gmail.com> explaining the reason.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(
    deprecated,
    improper_ctypes,
    non_shorthand_field_patterns,
    nonstandard_style,
    no_mangle_generic_items,
    unknown_lints,
    type_alias_bounds,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    rust_2018_idioms,
    unused,
    future_incompatible,
    clippy::all
)]
#![forbid(
    unconditional_recursion,
    unsafe_code,
    rustdoc::broken_intra_doc_links,
    while_true,
    elided_lifetimes_in_paths
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod das;
mod sequence;
mod time;
use ring::io::der;
mod spki;
pub use das::DataAlgorithmSignature;
pub use sequence::{ExtensionIterator, SequenceIterator};
pub use spki::{parse_algorithmid, Restrictions, SubjectPublicKeyInfo};

pub use time::{days_from_ymd, seconds_from_hms, ASN1Time, MAX_ASN1_TIMESTAMP, MIN_ASN1_TIMESTAMP};

#[cfg(feature = "rustls")]
pub use r::SignatureScheme;

/// A signature scheme supported by this library
#[cfg(not(feature = "rustls"))]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[derive(Eq, PartialEq, Debug, Hash, Clone, Copy)]
pub enum SignatureScheme {
    /// RSA PKCS#1 signatures with SHA256
    RSA_PKCS1_SHA256,
    /// RSA PKCS#1 signatures with SHA384
    RSA_PKCS1_SHA384,
    /// RSA PKCS#1 signatures with SHA512
    RSA_PKCS1_SHA512,
    /// ECDSA signatures with SHA256
    ECDSA_NISTP256_SHA256,
    /// ECDSA signatures with SHA384
    ECDSA_NISTP384_SHA384,
    /// ed25519 signatures
    ED25519,
    /// RSA-PSS signatures with SHA256
    RSA_PSS_SHA256,
    /// RSA-PSS signatures with SHA384
    RSA_PSS_SHA384,
    /// RSA-PSS signatures with SHA512
    RSA_PSS_SHA512,
    /// ed448 signatures
    ED448,
}

/// Errors that can be produced when parsing a certificate or validating a
/// signature.
///
/// More errors may be added in the future.
#[cfg(not(feature = "webpki"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "webpki"))))]
#[non_exhaustive]
#[derive(Eq, PartialEq, Debug, Hash, Clone, Copy)]
pub enum Error {
    /// Version is not valid.  Without the `legacy-certificates` feature, only
    /// X.509 v3 certificates are supported.  If the `legacy-certificates`
    /// feature is enabled, v1 and v2 certificates are also supported.
    UnsupportedCertVersion,
    /// Signature algorithm unsupported
    UnsupportedSignatureAlgorithm,
    /// Signature algorithm isn’t valid for the public key
    UnsupportedSignatureAlgorithmForPublicKey,
    /// Signature forged!
    InvalidSignatureForPublicKey,
    /// Signature algorithms don’t match
    SignatureAlgorithmMismatch,
    /// Invalid DER.  This will also result if the `legacy-certificates` feature
    /// is disabled, but one of the (obsolete and virtually unused)
    /// subjectUniqueId and issuerUniqueId fields are present.  Even if the
    /// `legacy-certificates` feature is enabled, these fields will not
    /// appear in the parsed certificate.
    BadDER,
    /// Invalid DER time
    BadDERTime,
    /// Certificate isn’t valid yet
    CertNotValidYet,
    /// Certificate has expired
    CertExpired,
    /// Certificate expired before beginning to be valid
    InvalidCertValidity,
    /// The issuer is not known.
    UnknownIssuer,
}

/// X509 certificate version
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[repr(u8)]
pub enum Version {
    /// Version 1
    V1 = 0,
    /// Version 2
    V2 = 1,
    /// Version 3
    V3 = 2,
}

#[cfg(feature = "webpki")]
pub use w::Error;

/// A parsed (but not validated) X.509 version 3 certificate.
#[derive(Debug)]
pub struct X509Certificate<'a> {
    das: DataAlgorithmSignature<'a>,
    serial: &'a [u8],
    issuer: &'a [u8],
    not_before: ASN1Time,
    not_after: ASN1Time,
    subject: &'a [u8],
    subject_public_key_info: SubjectPublicKeyInfo<'a>,
    #[cfg(feature = "obsolete-unique-ids")]
    issuer_unique_id: Option<untrusted::Input<'a>>,
    #[cfg(feature = "obsolete-unique-ids")]
    subject_unique_id: Option<untrusted::Input<'a>>,
    extensions: ExtensionIterator<'a>,
}

impl<'a> X509Certificate<'a> {
    /// The tbsCertificate, signatureAlgorithm, and signature
    pub fn das(&self) -> DataAlgorithmSignature<'a> { self.das }

    /// The serial number. Big-endian and non-empty. The first byte is
    /// guaranteed to be non-zero.
    pub fn serial(&self) -> &'a [u8] { self.serial }

    /// The X.509 issuer. This has not been validated and is not trusted. In
    /// particular, it is not guaranteed to be valid ASN.1 DER.
    pub fn issuer(&self) -> &'a [u8] { self.issuer }

    /// The earliest time, in seconds since the Unix epoch, that the certificate
    /// is valid.
    ///
    /// Will always be between [`MIN_ASN1_TIMESTAMP`] and
    /// [`MAX_ASN1_TIMESTAMP`], inclusive.
    pub fn not_before(&self) -> ASN1Time { self.not_before }

    /// The latest time, in seconds since the Unix epoch, that the certificate
    /// is valid.
    ///
    /// Will always be between [`MIN_ASN1_TIMESTAMP`] and
    /// [`MAX_ASN1_TIMESTAMP`], inclusive.
    pub fn not_after(&self) -> ASN1Time { self.not_after }

    /// X.509 subject. This has not been validated and is not trusted. In
    /// particular, it is not guaranteed to be valid ASN.1 DER.
    pub fn subject(&self) -> &'a [u8] { self.subject }

    /// The subjectPublicKeyInfo, encoded as ASN.1 DER. There is no guarantee
    /// that the OID or public key are valid ASN.1 DER, but if they are not,
    /// all methods that check signatures will fail.
    pub fn subject_public_key_info(&self) -> SubjectPublicKeyInfo<'a> {
        self.subject_public_key_info
    }

    /// An iterator over the certificate’s extensions.
    pub fn extensions(&self) -> ExtensionIterator<'a> { self.extensions }

    /// Verify a signature made by the certificate.
    pub fn check_signature(
        &self, algorithm: SignatureScheme, message: &[u8], signature: &[u8],
    ) -> Result<(), Error> {
        self.subject_public_key_info.check_signature(
            algorithm,
            message,
            signature,
            Restrictions::None,
        )
    }

    /// Retrieve the `issuerUniqueId` field of the certificate.
    ///
    /// This field is obsolete, so it will virtually always be `None`.  The data
    /// is returned as an ASN.1 encoded BIT STRING.
    #[cfg(feature = "obsolete-unique-ids")]
    #[cfg_attr(docsrs, doc(cfg(feature = "obsolete-unique-ids")))]
    pub fn issuer_unique_id(&self) -> Option<untrusted::Input<'a>> { self.issuer_unique_id }

    /// Retrieve the `subjectUniqueId` field of the certificate.
    ///
    /// This field is obsolete, so it will virtually always be `None`.  The data
    /// is returned as an ASN.1 encoded BIT STRING.
    #[cfg(feature = "obsolete-unique-ids")]
    #[cfg_attr(docsrs, doc(cfg(feature = "obsolete-unique-ids")))]
    pub fn subject_unique_id(&self) -> Option<untrusted::Input<'a>> { self.subject_unique_id }

    /// Verify a signature made by the certificate, applying the restrictions of
    /// TLSv1.3:
    ///
    /// * ECDSA algorithms where the hash has a different size than the curve
    ///   are not allowed.
    /// * RSA PKCS1.5 signatures are not allowed.
    ///
    /// This is a good choice for new protocols and applications. Note that
    /// extensions are not checked, so applications must process extensions
    /// themselves.
    pub fn check_tls13_signature(
        &self, algorithm: SignatureScheme, message: &[u8], signature: &[u8],
    ) -> Result<(), Error> {
        self.subject_public_key_info.check_signature(
            algorithm,
            message,
            signature,
            Restrictions::TLSv13,
        )
    }

    /// Verify a signature made by the certificate, applying the restrictions of
    /// TLSv1.2:
    ///
    /// * RSA-PSS signatures are not allowed.
    ///
    /// This should not be used outside of a TLSv1.2 implementation. Note that
    /// extensions are not checked, so applications must process extensions
    /// themselves.
    pub fn check_tls12_signature(
        &self, algorithm: SignatureScheme, message: &[u8], signature: &[u8],
    ) -> Result<(), Error> {
        self.subject_public_key_info.check_signature(
            algorithm,
            message,
            signature,
            Restrictions::TLSv12,
        )
    }

    /// Check that the certificate is valid at time `now`, in seconds since the
    /// Epoch.
    pub fn valid_at_timestamp(&self, now: i64) -> Result<(), Error> {
        if now < self.not_before.into() {
            Err(Error::CertNotValidYet)
        } else if now > self.not_after.into() {
            Err(Error::CertExpired)
        } else {
            Ok(())
        }
    }

    /// Check if a certificate is currently valid.
    #[cfg(feature = "std")]
    pub fn valid(&self) -> Result<(), Error> { self.valid_at_timestamp(ASN1Time::now()?.into()) }

    /// The tbsCertficate
    pub fn tbs_certificate(&self) -> &[u8] { self.das.data() }

    /// The `AlgorithmId` of the algorithm used to sign this certificate
    pub fn signature_algorithm_id(&self) -> &[u8] { self.das.algorithm() }

    /// The signature of the certificate
    pub fn signature(&self) -> &[u8] { self.das.signature() }

    /// Verify that this certificate was signed by `cert`’s secret key.
    ///
    /// This does not check that `cert` is a certificate authority.
    pub fn check_signature_from(&self, cert: &X509Certificate<'_>) -> Result<(), Error> {
        cert.check_signature(
            parse_algorithmid(self.signature_algorithm_id())?,
            self.tbs_certificate(),
            self.signature(),
        )
    }

    /// As above, but also check that `self`’s issuer is `cert`’s subject.
    pub fn check_issued_by(&self, cert: &X509Certificate<'_>) -> Result<(), Error> {
        if self.issuer != cert.subject {
            return Err(Error::UnknownIssuer);
        }
        self.check_signature_from(cert)
    }

    /// Check that this certificate is self-signed. This does not check that the
    /// subject and issuer are equal.
    #[deprecated(since = "0.3.3", note = "Use check_self_issued instead")]
    pub fn check_self_signature(&self) -> Result<(), Error> { self.check_signature_from(self) }

    /// Check that this certificate is self-signed, and that the subject and
    /// issuer are equal.
    pub fn check_self_issued(&self) -> Result<(), Error> { self.check_issued_by(self) }
}

fn parse_input<'a>(
    input: &mut untrusted::Reader<'a>, das: DataAlgorithmSignature<'a>,
) -> Result<X509Certificate<'a>, Error> {
    #[cfg(feature = "obsolete-unique-ids")]
    const CONTEXT_SPECIFIC_PRIMITIVE_1: u8 = der::CONTEXT_SPECIFIC | 1;
    #[cfg(feature = "obsolete-unique-ids")]
    const CONTEXT_SPECIFIC_PRIMITIVE_2: u8 = der::CONTEXT_SPECIFIC | 2;
    const CONTEXT_SPECIFIC_CONSTRUCTED_3: u8 = der::Tag::ContextSpecificConstructed3 as _;
    #[cfg(not(feature = "legacy-certificates"))]
    if input
        .read_bytes(5)
        .map_err(|_| Error::BadDer)?
        .as_slice_less_safe()
        != untrusted::Input::from(&[160, 3, 2, 1, 2]).as_slice_less_safe()
    {
        return Err(Error::UnsupportedCertVersion);
    }
    #[cfg(not(feature = "legacy-certificates"))]
    let version = Version::V3;
    #[cfg(feature = "legacy-certificates")]
    let version = if input.peek(160) {
        match *input
            .read_bytes(5)
            .map_err(|_| Error::BadDer)?
            .as_slice_less_safe()
        {
            [160, 3, 2, 1, 2] => Version::V3,
            [160, 3, 2, 1, 1] => Version::V2,
            [160, 3, 2, _, _] => return Err(Error::UnsupportedCertVersion),
            _ => return Err(Error::BadDer),
        }
    } else {
        Version::V1
    };
    // serialNumber
    let serial = der::positive_integer(input)
        .map_err(|_| Error::BadDer)?
        .big_endian_without_leading_zero();
    // signature
    if das::read_sequence(input)?.as_slice_less_safe() != das.algorithm() {
        // signature algorithms don’t match
        return Err(Error::SignatureAlgorithmMismatch);
    }
    // issuer
    let issuer = das::read_sequence(input)?.as_slice_less_safe();
    // validity
    let (not_before, not_after) = der::nested(input, der::Tag::Sequence, Error::BadDer, |input| {
        Ok((time::read_time(input)?, time::read_time(input)?))
    })?;
    if not_before > not_after {
        return Err(Error::InvalidCertValidity);
    }
    let subject = das::read_sequence(input)?.as_slice_less_safe();
    let subject_public_key_info = SubjectPublicKeyInfo::read(input)?;
    let mut extensions = None;
    #[cfg(feature = "obsolete-unique-ids")]
    let mut last_tag = 0;
    #[cfg(feature = "obsolete-unique-ids")]
    let mut unique_ids = [None; 2];
    #[cfg_attr(not(feature = "obsolete-unique-ids"), allow(clippy::never_loop))]
    while !input.at_end() {
        let (tag, value) = der::read_tag_and_get_value(input).map_err(|_| Error::BadDer)?;
        #[cfg(feature = "obsolete-unique-ids")]
        if tag <= last_tag {
            return Err(Error::BadDer);
        } else {
            last_tag = tag;
        }
        match tag {
            #[cfg(feature = "obsolete-unique-ids")]
            CONTEXT_SPECIFIC_PRIMITIVE_1 | CONTEXT_SPECIFIC_PRIMITIVE_2
                if version >= Version::V2 =>
            {
                match *value.as_slice_less_safe() {
                    [0, ..] => {},
                    [unused_bits, .., last]
                        if unused_bits < 8 && last.trailing_zeros() >= unused_bits.into() => {},
                    _ => return Err(Error::BadDer),
                }
                unique_ids[usize::from(tag - CONTEXT_SPECIFIC_PRIMITIVE_1)] = Some(value)
            },
            CONTEXT_SPECIFIC_CONSTRUCTED_3 if version >= Version::V3 => {
                let extension_data = value.read_all(Error::BadDer, das::read_sequence)?;
                if extension_data.as_slice_less_safe().is_empty() {
                    return Err(Error::BadDer);
                }
                extensions = Some(extension_data);
                break;
            },
            _ => return Err(Error::BadDer),
        }
    }

    let extensions = ExtensionIterator(SequenceIterator::read(&mut untrusted::Reader::new(
        extensions.unwrap_or_else(|| untrusted::Input::from(b"")),
    )));

    Ok(X509Certificate {
        das,
        serial,
        subject,
        not_before,
        not_after,
        issuer,
        subject_public_key_info,
        #[cfg(feature = "obsolete-unique-ids")]
        issuer_unique_id: unique_ids[0],
        #[cfg(feature = "obsolete-unique-ids")]
        subject_unique_id: unique_ids[1],
        extensions,
    })
}

/// Extracts the algorithm id and public key from a certificate
pub fn parse_certificate(certificate: &[u8]) -> Result<X509Certificate<'_>, Error> {
    use core::convert::TryFrom as _;
    let das = DataAlgorithmSignature::try_from(certificate)?;
    untrusted::Input::from(das.inner()).read_all(Error::BadDer, |i| parse_input(i, das))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_openssl_generated_cert() {
        let signature = include_bytes!("../testing.sig");
        let invalid_signature = include_bytes!("../testing.bad-sig");
        let forged_message = include_bytes!("../forged-message.txt");
        let message = include_bytes!("../gen-bad-cert.sh");
        let certificate = include_bytes!("../testing.crt");
        #[cfg(feature = "rsa")]
        let ca_certificate = include_bytes!("../ca.crt");

        let cert = parse_certificate(certificate).unwrap();
        #[cfg(feature = "rsa")]
        let ca_cert = parse_certificate(ca_certificate).unwrap();
        assert_eq!(
            cert.subject_public_key_info.algorithm(),
            include_bytes!("data/alg-ecdsa-p256.der")
        );
        assert_eq!(cert.subject_public_key_info.key().len(), 65);
        cert.valid_at_timestamp(1587492766).unwrap();
        assert_eq!(cert.valid_at_timestamp(0), Err(Error::CertNotValidYet));
        assert_eq!(
            cert.valid_at_timestamp(i64::max_value()),
            Err(Error::CertExpired)
        );

        cert.check_signature(SignatureScheme::ECDSA_NISTP256_SHA256, message, signature)
            .expect("OpenSSL generates syntactically valid certificates");
        assert_eq!(
            cert.check_signature(
                SignatureScheme::ECDSA_NISTP256_SHA256,
                message,
                invalid_signature,
            )
            .expect_err("corrupting a signature invalidates it"),
            Error::InvalidSignatureForPublicKey
        );
        assert_eq!(
            cert.check_signature(
                SignatureScheme::ECDSA_NISTP256_SHA256,
                message,
                invalid_signature,
            )
            .expect_err("corrupting a message invalidates it"),
            Error::InvalidSignatureForPublicKey
        );
        assert_eq!(
            cert.check_signature(
                SignatureScheme::ECDSA_NISTP256_SHA256,
                forged_message,
                signature,
            )
            .expect_err("forgery undetected?"),
            Error::InvalidSignatureForPublicKey
        );
        #[cfg(feature = "rsa")]
        ca_cert.check_self_issued().unwrap();
        #[cfg(feature = "rsa")]
        cert.check_issued_by(&ca_cert).unwrap();
        let mut extensions = vec![];
        cert.extensions()
            .iterate(&mut |oid, critical, e| {
                Ok(extensions.push((oid, critical, e.as_slice_less_safe())))
            })
            .unwrap();
        assert_eq!(extensions.len(), 6, "wrong number of extensions");
        assert_eq!(extensions[0], (&[85, 29, 19][..], true, &b"\x30\0"[..]));
        assert_eq!(extensions[1].0, &[85, 29, 14][..]);
        assert!(!extensions[1].1);
        assert_eq!(extensions[1].2.len(), 22);
        assert_eq!(extensions[1].2[..2], b"\x04\x14"[..]);
    }
}
