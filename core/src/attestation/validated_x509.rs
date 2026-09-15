//! Internal Ed25519 X.509 client-certificate profile, not an attestation verdict.
//! Trusted roots, time and expected DNS identity must come from verifier policy.
//! CRLs are mandatory for the entire non-root chain; no OCSP soft-fail fallback.
//! Identity/commitment binding, possession and persistent rollback state remain
//! separate release gates. This module is not exported in normal builds.

use crate::{Result, SableError};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::{collections::HashSet, time::Duration};
use webpki::{
    BorrowedCertRevocationList, CertRevocationList, EndEntityCert, ExpirationPolicy, KeyUsage,
    RevocationCheckDepth, RevocationOptionsBuilder, UnknownStatusPolicy,
};
use x509_parser::{parse_x509_certificate, parse_x509_crl};

const MAX_CERT: usize = 16 * 1024;
const MAX_CRL: usize = 256 * 1024;

fn denied() -> SableError {
    SableError::Cryptographic("Certificate validation rejected".into())
}

fn certificate_policy(der: &[u8], ca: bool, now: i64) -> Result<()> {
    if der.is_empty() || der.len() > MAX_CERT {
        return Err(denied());
    }
    let (rest, cert) = parse_x509_certificate(der).map_err(|_| denied())?;
    let public = cert.public_key();
    if public.algorithm.algorithm.to_id_string() != "1.3.101.112"
        || public.algorithm.parameters.is_some()
        || public.subject_public_key.unused_bits != 0
        || public.subject_public_key.data.len() != 32
    {
        return Err(denied());
    }
    if !rest.is_empty()
        || now < cert.validity().not_before.timestamp()
        || now >= cert.validity().not_after.timestamp()
    {
        return Err(denied());
    }
    // Duplicate extension OIDs are never resolved by selecting a convenient copy.
    let mut seen = HashSet::new();
    if cert
        .extensions()
        .iter()
        .any(|ext| !seen.insert(ext.oid.to_id_string()))
    {
        return Err(denied());
    }
    let constraints = cert.basic_constraints().map_err(|_| denied())?;
    if constraints
        .as_ref()
        .map(|ext| ext.value.ca)
        .unwrap_or(false)
        != ca
    {
        return Err(denied());
    }
    let usage = cert.key_usage().map_err(|_| denied())?.ok_or_else(denied)?;
    if ca {
        if !usage.value.key_cert_sign() || !usage.value.crl_sign() {
            return Err(denied());
        }
    } else {
        if !usage.value.digital_signature() || usage.value.key_cert_sign() || usage.value.crl_sign()
        {
            return Err(denied());
        }
        let eku = cert
            .extended_key_usage()
            .map_err(|_| denied())?
            .ok_or_else(denied)?;
        if !eku.value.client_auth || eku.value.any {
            return Err(denied());
        }
    }
    Ok(())
}

/// Validate a bounded certificate bundle under a strict client-auth profile.
/// Success means chain/name/revocation policy passed, NOT possession or capture.
pub(super) fn validate_chain(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    roots: &[Vec<u8>],
    crls: &[Vec<u8>],
    expected_name: &str,
    now: u64,
) -> Result<()> {
    if roots.is_empty()
        || roots.len() > 16
        || intermediates.len() > 4
        || crls.is_empty()
        || crls.len() > 16
    {
        return Err(denied());
    }
    let time = i64::try_from(now).map_err(|_| denied())?;
    certificate_policy(leaf, false, time)?;
    for cert in roots.iter().chain(intermediates) {
        certificate_policy(cert, true, time)?;
    }

    let mut issuers = HashSet::new();
    for der in crls {
        if der.is_empty() || der.len() > MAX_CRL {
            return Err(denied());
        }
        let (rest, crl) = parse_x509_crl(der).map_err(|_| denied())?;
        let next = crl.next_update().ok_or_else(denied)?.timestamp();
        if !rest.is_empty()
            || crl.last_update().timestamp() > time
            || next <= time
            || next <= crl.last_update().timestamp()
        {
            return Err(denied());
        }
        // Overlapping CRLs for one issuer need an authenticated monotonic version
        // selection policy. Reject ambiguity until that trust-store layer exists.
        if !issuers.insert(crl.issuer().as_raw().to_vec()) {
            return Err(denied());
        }
    }
    let roots: Vec<_> = roots
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    let anchors = roots
        .iter()
        .map(webpki::anchor_from_trusted_cert)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| denied())?;
    let intermediates: Vec<_> = intermediates
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    let lists: Vec<CertRevocationList<'_>> = crls
        .iter()
        .map(|der| BorrowedCertRevocationList::from_der(der).map(Into::into))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| denied())?;
    let refs: Vec<_> = lists.iter().collect();
    let revocation = RevocationOptionsBuilder::new(&refs)
        .map_err(|_| denied())?
        .with_depth(RevocationCheckDepth::Chain)
        .with_status_policy(UnknownStatusPolicy::Deny)
        .with_expiration_policy(ExpirationPolicy::Enforce)
        .build();
    let leaf = CertificateDer::from(leaf);
    let cert = EndEntityCert::try_from(&leaf).map_err(|_| denied())?;
    cert.verify_for_usage(
        &[webpki::ring::ED25519],
        &anchors,
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(now)),
        KeyUsage::client_auth(),
        Some(revocation),
        None,
    )
    .map_err(|_| denied())?;
    let name = ServerName::try_from(expected_name).map_err(|_| denied())?;
    cert.verify_is_valid_for_subject_name(&name)
        .map_err(|_| denied())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, CertificateRevocationListParams,
        CertifiedIssuer, DistinguishedName, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa,
        KeyIdMethod, KeyPair, KeyUsagePurpose, NameConstraints, RevokedCertParams, SerialNumber,
        PKCS_ED25519,
    };

    fn key() -> KeyPair {
        KeyPair::generate_for(&PKCS_ED25519).unwrap()
    }
    fn now() -> u64 {
        date_time_ymd(2026, 9, 15).unix_timestamp() as u64
    }
    fn params(name: &str, ca: bool, serial: u64) -> CertificateParams {
        let mut p =
            CertificateParams::new(if ca { vec![] } else { vec![name.to_owned()] }).unwrap();
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, name);
        p.not_before = date_time_ymd(2026, 9, 1);
        p.not_after = date_time_ymd(2026, 10, 1);
        p.serial_number = Some(serial.into());
        p.is_ca = if ca {
            IsCa::Ca(BasicConstraints::Unconstrained)
        } else {
            IsCa::ExplicitNoCa
        };
        p.key_usages = if ca {
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]
        } else {
            vec![KeyUsagePurpose::DigitalSignature]
        };
        if !ca {
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        }
        p
    }

    fn crl(
        issuer: &CertifiedIssuer<'_, KeyPair>,
        revoked: Option<u64>,
        start_day: u8,
        end_day: u8,
    ) -> Vec<u8> {
        CertificateRevocationListParams {
            this_update: date_time_ymd(2026, 9, start_day),
            next_update: date_time_ymd(2026, 9, end_day),
            crl_number: 1u64.into(),
            issuing_distribution_point: None,
            key_identifier_method: KeyIdMethod::Sha256,
            revoked_certs: revoked
                .into_iter()
                .map(|serial| RevokedCertParams {
                    serial_number: SerialNumber::from(serial),
                    revocation_time: date_time_ymd(2026, 9, 14),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
        }
        .signed_by(issuer)
        .unwrap()
        .der()
        .to_vec()
    }

    struct Bundle {
        root: CertifiedIssuer<'static, KeyPair>,
        intermediate: CertifiedIssuer<'static, KeyPair>,
        leaf: Vec<u8>,
        lists: Vec<Vec<u8>>,
    }
    impl Bundle {
        fn new(
            change_ca: impl FnOnce(&mut CertificateParams),
            change_leaf: impl FnOnce(&mut CertificateParams),
        ) -> Self {
            let root = CertifiedIssuer::self_signed(params("Root", true, 1), key()).unwrap();
            let mut p = params("Intermediate", true, 2);
            change_ca(&mut p);
            let intermediate = CertifiedIssuer::signed_by(p, key(), &root).unwrap();
            let mut p = params("device.allowed.test", false, 3);
            change_leaf(&mut p);
            let leaf = p.signed_by(&key(), &intermediate).unwrap().der().to_vec();
            let lists = vec![crl(&root, None, 14, 16), crl(&intermediate, None, 14, 16)];
            Self {
                root,
                intermediate,
                leaf,
                lists,
            }
        }
        fn verify(&self) -> Result<()> {
            validate_chain(
                &self.leaf,
                &[self.intermediate.der().to_vec()],
                &[self.root.der().to_vec()],
                &self.lists,
                "device.allowed.test",
                now(),
            )
        }
    }

    #[test]
    fn valid_der_chain_and_signed_crls_pass() {
        Bundle::new(|_| {}, |_| {}).verify().unwrap();
    }

    #[test]
    fn unsupported_leaf_key_and_unknown_critical_extension_fail() {
        let mut b = Bundle::new(|_| {}, |_| {});
        b.leaf = params("device.allowed.test", false, 3)
            .signed_by(&KeyPair::generate().unwrap(), &b.intermediate)
            .unwrap()
            .der()
            .to_vec();
        assert!(b.verify().is_err());
        let b = Bundle::new(
            |_| {},
            |p| {
                let mut extension =
                    rcgen::CustomExtension::from_oid_content(&[1, 2, 3, 4, 5], vec![5, 0]);
                extension.set_criticality(true);
                p.custom_extensions.push(extension);
            },
        );
        assert!(b.verify().is_err());
    }

    #[test]
    fn intermediate_path_length_is_enforced() {
        for constrained in [false, true] {
            let b = Bundle::new(
                |p| {
                    if constrained {
                        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
                    }
                },
                |_| {},
            );
            let child =
                CertifiedIssuer::signed_by(params("Child", true, 4), key(), &b.intermediate)
                    .unwrap();
            let leaf = params("device.allowed.test", false, 5)
                .signed_by(&key(), &child)
                .unwrap();
            let mut crls = b.lists.clone();
            crls.push(crl(&child, None, 14, 16));
            let result = validate_chain(
                leaf.der(),
                &[child.der().to_vec(), b.intermediate.der().to_vec()],
                &[b.root.der().to_vec()],
                &crls,
                "device.allowed.test",
                now(),
            );
            assert_eq!(result.is_ok(), !constrained);
        }
    }

    #[test]
    fn same_name_crl_signed_by_wrong_key_is_rejected() {
        let mut b = Bundle::new(|_| {}, |_| {});
        let imposter =
            CertifiedIssuer::signed_by(params("Intermediate", true, 2), key(), &b.root).unwrap();
        b.lists[1] = crl(&imposter, None, 14, 16);
        assert!(b.verify().is_err());
    }

    #[test]
    fn modified_leaf_tbs_and_signatures_are_rejected() {
        let mut b = Bundle::new(|_| {}, |_| {});
        b.verify().unwrap();
        let original = b.leaf.clone();
        let offset = b
            .leaf
            .windows(b"device.allowed.test".len())
            .position(|v| v == b"device.allowed.test")
            .unwrap();
        b.leaf[offset] ^= 1;
        assert!(b.verify().is_err());
        b.leaf = original.clone();
        let last = b.leaf.len() - 1;
        b.leaf[last] ^= 1;
        assert!(b.verify().is_err());
        for candidate in 0..32u8 {
            b.leaf = original.clone();
            let start = b.leaf.len() - 64;
            b.leaf[start..].fill(candidate);
            assert!(b.verify().is_err());
        }
    }

    #[test]
    fn unknown_root_wrong_name_and_missing_intermediate_fail() {
        let b = Bundle::new(|_| {}, |_| {});
        let wrong = CertifiedIssuer::self_signed(params("Root", true, 1), key()).unwrap();
        assert!(validate_chain(
            &b.leaf,
            &[b.intermediate.der().to_vec()],
            &[wrong.der().to_vec()],
            &b.lists,
            "device.allowed.test",
            now()
        )
        .is_err());
        assert!(validate_chain(
            &b.leaf,
            &[b.intermediate.der().to_vec()],
            &[b.root.der().to_vec()],
            &b.lists,
            "attacker.test",
            now()
        )
        .is_err());
        assert!(validate_chain(
            &b.leaf,
            &[],
            &[b.root.der().to_vec()],
            &b.lists,
            "device.allowed.test",
            now()
        )
        .is_err());
    }

    #[test]
    fn non_ca_and_wrong_key_usage_intermediates_fail() {
        assert!(Bundle::new(|p| p.is_ca = IsCa::ExplicitNoCa, |_| {})
            .verify()
            .is_err());
        assert!(
            Bundle::new(|p| p.key_usages = vec![KeyUsagePurpose::CrlSign], |_| {})
                .verify()
                .is_err()
        );
    }

    #[test]
    fn invalid_leaf_usage_and_validity_fail() {
        for case in 0..6 {
            let b = Bundle::new(
                |_| {},
                |p| match case {
                    0 => p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth],
                    1 => p.extended_key_usages.clear(),
                    2 => p.key_usages = vec![KeyUsagePurpose::KeyEncipherment],
                    3 => p.not_after = date_time_ymd(2026, 9, 15),
                    4 => p.not_before = date_time_ymd(2026, 9, 16),
                    _ => p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained),
                },
            );
            assert!(b.verify().is_err(), "case {case}");
        }
    }

    #[test]
    fn name_constraints_are_enforced() {
        let constrained = |p: &mut CertificateParams| {
            p.name_constraints = Some(NameConstraints {
                permitted_subtrees: vec![GeneralSubtree::DnsName("allowed.test".into())],
                excluded_subtrees: vec![],
            })
        };
        Bundle::new(constrained, |_| {}).verify().unwrap();
        let b = Bundle::new(constrained, |p| {
            p.subject_alt_names = CertificateParams::new(vec!["device.other.test".into()])
                .unwrap()
                .subject_alt_names
        });
        // Ask for the actual SAN, so failure proves the CA name constraint matters.
        assert!(validate_chain(
            &b.leaf,
            &[b.intermediate.der().to_vec()],
            &[b.root.der().to_vec()],
            &b.lists,
            "device.other.test",
            now()
        )
        .is_err());
    }

    #[test]
    fn revoked_leaf_and_intermediate_fail() {
        let mut b = Bundle::new(|_| {}, |_| {});
        b.lists[1] = crl(&b.intermediate, Some(3), 14, 16);
        assert!(b.verify().is_err());
        b.lists[1] = crl(&b.intermediate, None, 14, 16);
        b.lists[0] = crl(&b.root, Some(2), 14, 16);
        assert!(b.verify().is_err());
    }

    #[test]
    fn missing_stale_future_tampered_and_ambiguous_crls_fail() {
        for case in 0..7 {
            let mut b = Bundle::new(|_| {}, |_| {});
            match case {
                0 => b.lists.clear(),
                1 => {
                    b.lists.remove(0);
                }
                2 => {
                    b.lists.remove(1);
                }
                3 => b.lists[1] = crl(&b.intermediate, None, 13, 15),
                4 => b.lists[1] = crl(&b.intermediate, None, 16, 17),
                5 => {
                    let last = b.lists[1].len() - 1;
                    b.lists[1][last] ^= 1;
                }
                _ => b.lists.push(b.lists[1].clone()),
            }
            assert!(b.verify().is_err(), "case {case}");
        }
    }

    #[test]
    fn trailing_der_bytes_and_resource_limits_fail() {
        let mut b = Bundle::new(|_| {}, |_| {});
        b.leaf.push(0);
        assert!(b.verify().is_err());
        b.leaf.pop();
        b.lists[1].push(0);
        assert!(b.verify().is_err());
        b.lists[1].pop();
        b.lists[1].resize(MAX_CRL + 1, 0);
        assert!(b.verify().is_err());
        assert!(validate_chain(
            &b.leaf,
            &vec![vec![]; 5],
            &[],
            &[],
            "device.allowed.test",
            now()
        )
        .is_err());
    }
}
