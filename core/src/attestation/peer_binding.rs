//! Internal certificate-key possession binding; not a capture attestation.
//! All policy fields come from trusted registration/challenge state. The peer
//! contributes only a Noise public key, certificate bundle and signature.
//! Persistent trust/revocation rollback controls remain required before release.

use super::validated_x509::validate_chain;
use crate::{Result, SableError};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const DOMAIN: &[u8] = b"sable/certificate-noise-binding/1\0";

#[derive(Clone)]
struct BindingPolicy {
    expected_name: String,
    registered_template: [u8; 32],
    audience: [u8; 32],
    challenge: [u8; 32],
    session: [u8; 16],
    peer_role: u8,
    issued_at: u64,
    expires_at: u64,
}

impl BindingPolicy {
    fn validate(&self, now: u64) -> Result<()> {
        let lifetime = self
            .expires_at
            .checked_sub(self.issued_at)
            .ok_or_else(denied)?;
        if !(1..=30).contains(&lifetime)
            || now < self.issued_at
            || now >= self.expires_at
            || self.peer_role > 1
            || self.expected_name.is_empty()
            || self.expected_name.len() > 253
        {
            return Err(denied());
        }
        Ok(())
    }

    fn message(&self, leaf_digest: &[u8; 32], noise_key: &[u8; 32]) -> Vec<u8> {
        let mut bytes = DOMAIN.to_vec();
        // Fixed-width fields except DNS identity, which has an explicit length.
        bytes.extend_from_slice(&(self.expected_name.len() as u16).to_be_bytes());
        bytes.extend_from_slice(self.expected_name.as_bytes());
        bytes.extend_from_slice(leaf_digest);
        bytes.extend_from_slice(&self.registered_template);
        bytes.extend_from_slice(&self.audience);
        bytes.extend_from_slice(&self.challenge);
        bytes.extend_from_slice(&self.session);
        bytes.push(self.peer_role);
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(noise_key);
        bytes
    }
}

fn denied() -> SableError {
    SableError::Cryptographic("Certificate peer binding rejected".into())
}

/// Not Clone: a checked binding is intended to be consumed by one handshake.
pub(crate) struct VerifiedPeer {
    noise_key: [u8; 32],
    certificate_digest: [u8; 32],
    session: [u8; 16],
    role: u8,
    expires_at: u64,
    deadline: Instant,
}

impl VerifiedPeer {
    pub(crate) fn consume_for(
        self,
        session: [u8; 16],
        role: u8,
        now: u64,
    ) -> Result<([u8; 32], [u8; 32], Instant)> {
        if session != self.session
            || role != self.role
            || now >= self.expires_at
            || Instant::now() >= self.deadline
        {
            return Err(denied());
        }
        Ok((self.noise_key, self.certificate_digest, self.deadline))
    }
}

/// Single-use in-memory challenge. Persisted/global uniqueness is the future
/// challenge-store integration's responsibility; constructing a fresh object with
/// reused policy would bypass that responsibility. No public API is exported.
struct BindingChallenge(Option<BindingPolicy>);

impl BindingChallenge {
    fn verify(
        &mut self,
        leaf: &[u8],
        intermediates: &[Vec<u8>],
        roots: &[Vec<u8>],
        crls: &[Vec<u8>],
        noise_key: [u8; 32],
        signature: &[u8],
        now: u64,
    ) -> Result<VerifiedPeer> {
        let checked_at = Instant::now();
        // Consume before validation, including failed attempts. No fallback.
        let policy = self.0.take().ok_or_else(denied)?;
        policy.validate(now)?;
        if signature.len() != 64 || x25519_dalek::x25519([0x42; 32], noise_key) == [0; 32] {
            return Err(denied());
        }
        validate_chain(leaf, intermediates, roots, crls, &policy.expected_name, now)?;
        let digest: [u8; 32] = Sha256::digest(leaf).into();
        let message = policy.message(&digest, &noise_key);
        let leaf = CertificateDer::from(leaf);
        let cert = webpki::EndEntityCert::try_from(&leaf).map_err(|_| denied())?;
        cert.verify_signature(webpki::ring::ED25519, &message, signature)
            .map_err(|_| denied())?;
        // Do not let the binding extend any certificate or CRL validity window.
        // Taking all supplied entries is conservative if the path builder did not
        // need one of them. All entries have already passed bounded parsing.
        let mut expires_at = policy.expires_at;
        for der in std::iter::once(leaf.as_ref())
            .chain(intermediates.iter().map(Vec::as_slice))
            .chain(roots.iter().map(Vec::as_slice))
        {
            let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|_| denied())?;
            expires_at = expires_at
                .min(u64::try_from(cert.validity().not_after.timestamp()).map_err(|_| denied())?);
        }
        for der in crls {
            let (_, crl) = x509_parser::parse_x509_crl(der).map_err(|_| denied())?;
            expires_at = expires_at.min(
                u64::try_from(crl.next_update().ok_or_else(denied)?.timestamp())
                    .map_err(|_| denied())?,
            );
        }
        Ok(VerifiedPeer {
            noise_key,
            certificate_digest: digest,
            session: policy.session,
            role: policy.peer_role,
            expires_at,
            deadline: checked_at
                + Duration::from_secs(expires_at.checked_sub(now).ok_or_else(denied)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, CertificateRevocationListParams,
        CertifiedIssuer, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod,
        KeyPair, KeyUsagePurpose, SigningKey, PKCS_ED25519,
    };

    struct Fixture {
        leaf: Vec<u8>,
        key: KeyPair,
        roots: Vec<Vec<u8>>,
        crls: Vec<Vec<u8>>,
        policy: BindingPolicy,
        noise: [u8; 32],
    }
    impl Fixture {
        fn new() -> Self {
            Self::with_expiry(None, None)
        }
        fn with_expiry(cert_seconds: Option<u64>, crl_seconds: Option<u64>) -> Self {
            let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
            ca.distinguished_name = DistinguishedName::new();
            ca.distinguished_name
                .push(DnType::CommonName, "Binding Root");
            ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let issuer =
                CertifiedIssuer::self_signed(ca, KeyPair::generate_for(&PKCS_ED25519).unwrap())
                    .unwrap();
            let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let mut params = CertificateParams::new(vec!["peer.allowed.test".into()]).unwrap();
            params.is_ca = IsCa::ExplicitNoCa;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            if let Some(seconds) = cert_seconds {
                params.not_after = date_time_ymd(2026, 9, 15) + Duration::from_secs(seconds);
            }
            let leaf = params.signed_by(&key, &issuer).unwrap().der().to_vec();
            let crl = CertificateRevocationListParams {
                this_update: date_time_ymd(2026, 9, 14),
                next_update: crl_seconds
                    .map(|seconds| date_time_ymd(2026, 9, 15) + Duration::from_secs(seconds))
                    .unwrap_or_else(|| date_time_ymd(2026, 9, 16)),
                crl_number: 1u64.into(),
                issuing_distribution_point: None,
                revoked_certs: vec![],
                key_identifier_method: KeyIdMethod::Sha256,
            }
            .signed_by(&issuer)
            .unwrap()
            .der()
            .to_vec();
            let now = date_time_ymd(2026, 9, 15).unix_timestamp() as u64;
            Self {
                leaf,
                key,
                roots: vec![issuer.der().to_vec()],
                crls: vec![crl],
                policy: BindingPolicy {
                    expected_name: "peer.allowed.test".into(),
                    registered_template: [1; 32],
                    audience: [2; 32],
                    challenge: [3; 32],
                    session: [4; 16],
                    peer_role: 1,
                    issued_at: now,
                    expires_at: now + 30,
                },
                noise: x25519_dalek::x25519([9; 32], x25519_dalek::X25519_BASEPOINT_BYTES),
            }
        }
        fn signature(&self) -> Vec<u8> {
            self.key
                .sign(
                    &self
                        .policy
                        .message(&Sha256::digest(&self.leaf).into(), &self.noise),
                )
                .unwrap()
        }
        fn verify(
            &self,
            challenge: &mut BindingChallenge,
            sig: &[u8],
            now: u64,
        ) -> Result<VerifiedPeer> {
            challenge.verify(
                &self.leaf,
                &[],
                &self.roots,
                &self.crls,
                self.noise,
                sig,
                now,
            )
        }
    }

    #[test]
    fn possession_binds_certificate_template_noise_key_and_single_use_challenge() {
        let f = Fixture::new();
        let signature = f.signature();
        let mut challenge = BindingChallenge(Some(f.policy.clone()));
        let peer = f
            .verify(&mut challenge, &signature, f.policy.issued_at)
            .unwrap();
        assert_eq!(peer.noise_key, f.noise);
        assert_eq!(
            peer.certificate_digest,
            <[u8; 32]>::from(Sha256::digest(&f.leaf))
        );
        assert_eq!(peer.session, f.policy.session);
        assert_eq!(peer.role, f.policy.peer_role);
        assert_eq!(peer.expires_at, f.policy.expires_at);
        assert!(f
            .verify(&mut challenge, &signature, f.policy.issued_at)
            .is_err());
    }

    #[test]
    fn every_verifier_owned_binding_field_is_authenticated() {
        let f = Fixture::new();
        let signature = f.signature();
        for field in 0..8 {
            let mut policy = f.policy.clone();
            match field {
                0 => policy.registered_template[0] ^= 1,
                1 => policy.audience[0] ^= 1,
                2 => policy.challenge[0] ^= 1,
                3 => policy.session[0] ^= 1,
                4 => policy.peer_role ^= 1,
                5 => policy.issued_at += 1,
                6 => policy.expires_at -= 1,
                _ => policy.expected_name = "wrong.allowed.test".into(),
            }
            assert!(
                f.verify(
                    &mut BindingChallenge(Some(policy)),
                    &signature,
                    f.policy.issued_at + 2
                )
                .is_err(),
                "field {field}"
            );
        }
    }

    #[test]
    fn substituted_noise_key_or_certificate_cannot_reuse_signature() {
        let mut f = Fixture::new();
        let signature = f.signature();
        f.noise = x25519_dalek::x25519([8; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
        assert!(f
            .verify(
                &mut BindingChallenge(Some(f.policy.clone())),
                &signature,
                f.policy.issued_at
            )
            .is_err());
        let other = Fixture::new();
        // Even a fresh, otherwise valid certificate with the same DNS name and
        // accepted root cannot use a signature made under the original identity.
        assert!(other
            .verify(
                &mut BindingChallenge(Some(other.policy.clone())),
                &signature,
                other.policy.issued_at
            )
            .is_err());
    }

    #[test]
    fn invalid_signature_consumes_challenge_and_cannot_retry() {
        let f = Fixture::new();
        let signature = f.signature();
        for bad in [vec![], vec![0; 63], vec![0; 64], vec![0; 65]] {
            let mut challenge = BindingChallenge(Some(f.policy.clone()));
            assert!(f.verify(&mut challenge, &bad, f.policy.issued_at).is_err());
            assert!(f
                .verify(&mut challenge, &signature, f.policy.issued_at)
                .is_err());
        }
    }

    #[test]
    fn expiry_future_and_excessive_lifetime_fail_closed() {
        let f = Fixture::new();
        let signature = f.signature();
        for now in [f.policy.issued_at - 1, f.policy.expires_at, u64::MAX] {
            assert!(f
                .verify(
                    &mut BindingChallenge(Some(f.policy.clone())),
                    &signature,
                    now
                )
                .is_err());
        }
        for expires in [
            f.policy.issued_at,
            f.policy.issued_at - 1,
            f.policy.issued_at + 31,
        ] {
            let mut policy = f.policy.clone();
            policy.expires_at = expires;
            assert!(f
                .verify(
                    &mut BindingChallenge(Some(policy)),
                    &signature,
                    f.policy.issued_at
                )
                .is_err());
        }
    }

    #[test]
    fn valid_possession_does_not_bypass_revocation_or_key_validation() {
        let mut f = Fixture::new();
        let signature = f.signature();
        f.crls.clear();
        assert!(f
            .verify(
                &mut BindingChallenge(Some(f.policy.clone())),
                &signature,
                f.policy.issued_at
            )
            .is_err());
        let mut f = Fixture::new();
        f.noise = [0; 32];
        let signature = f.signature();
        assert!(f
            .verify(
                &mut BindingChallenge(Some(f.policy.clone())),
                &signature,
                f.policy.issued_at
            )
            .is_err());
    }

    #[test]
    fn certificate_bound_peers_complete_noise_and_exchange_records() {
        use crate::p2p::authenticated::{Handshake, Role};
        let mut a = Fixture::new();
        a.policy.peer_role = 0;
        let mut b = Fixture::new();
        b.noise = x25519_dalek::x25519([8; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
        let a_peer = a
            .verify(
                &mut BindingChallenge(Some(a.policy.clone())),
                &a.signature(),
                a.policy.issued_at,
            )
            .unwrap();
        let b_peer = b
            .verify(
                &mut BindingChallenge(Some(b.policy.clone())),
                &b.signature(),
                b.policy.issued_at,
            )
            .unwrap();
        let mut a_channel = Handshake::with_verified_peer(
            &[9; 32],
            b_peer,
            Sha256::digest(&a.leaf).into(),
            a.policy.session,
            Role::Initiator,
            a.policy.issued_at,
        )
        .unwrap();
        let mut b_channel = Handshake::with_verified_peer(
            &[8; 32],
            a_peer,
            Sha256::digest(&b.leaf).into(),
            b.policy.session,
            Role::Responder,
            b.policy.issued_at,
        )
        .unwrap();
        b_channel.read(&a_channel.write().unwrap()).unwrap();
        a_channel.read(&b_channel.write().unwrap()).unwrap();
        b_channel.read(&a_channel.write().unwrap()).unwrap();
        let mut a_channel = a_channel.finish().unwrap();
        let mut b_channel = b_channel.finish().unwrap();
        assert_eq!(
            b_channel
                .open(1, &a_channel.seal(1, b"proof").unwrap())
                .unwrap(),
            b"proof"
        );
        assert_eq!(
            a_channel
                .open(2, &b_channel.seal(2, b"result").unwrap())
                .unwrap(),
            b"result"
        );
    }

    #[test]
    fn checked_binding_cannot_be_used_for_another_session_role_or_after_expiry() {
        use crate::p2p::authenticated::{Handshake, Role};
        let f = Fixture::new();
        for case in 0..4 {
            let mut peer = f
                .verify(
                    &mut BindingChallenge(Some(f.policy.clone())),
                    &f.signature(),
                    f.policy.issued_at,
                )
                .unwrap();
            let mut session = f.policy.session;
            let mut role = Role::Initiator;
            let mut now = f.policy.issued_at;
            match case {
                0 => session[0] ^= 1,
                1 => role = Role::Responder,
                2 => now = f.policy.expires_at,
                _ => peer.deadline = Instant::now(),
            }
            assert!(
                Handshake::with_verified_peer(&[8; 32], peer, [7; 32], session, role, now).is_err()
            );
        }
    }

    #[test]
    fn binding_cannot_extend_certificate_or_crl_validity() {
        for (cert, crl, expected) in [
            (Some(2), None, 2),
            (None, Some(3), 3),
            (Some(5), Some(4), 4),
        ] {
            let f = Fixture::with_expiry(cert, crl);
            let peer = f
                .verify(
                    &mut BindingChallenge(Some(f.policy.clone())),
                    &f.signature(),
                    f.policy.issued_at,
                )
                .unwrap();
            assert_eq!(peer.expires_at, f.policy.issued_at + expected);
            assert!(peer
                .consume_for(
                    f.policy.session,
                    f.policy.peer_role,
                    f.policy.issued_at + expected
                )
                .is_err());
        }
    }
}
