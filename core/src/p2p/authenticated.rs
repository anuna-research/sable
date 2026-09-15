//! Internal replacement under test, NOT an exported or attested channel.
//!
//! Noise XX authenticates possession of pinned static keys. The pin and identity
//! digests below must ultimately come from validated attestation, not the wire.
//! This module stays test-only until that integration and transport migration.
//! The application record layer is deliberately distinct from Noise transport:
//! consumed XX split keys feed HKDF-SHA256 with transcript/context/direction;
//! ChaCha20-Poly1305 authenticates a fixed-width header as associated data.

use crate::{Result, SableError};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const DOMAIN: &[u8] = b"sable/p2p/attested-channel/1";
const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PAYLOAD: usize = 64 * 1024;
const HEADER_LEN: usize = 35;

fn failure() -> SableError {
    SableError::Cryptographic("P2P authentication or channel state rejected".into())
}

fn contributory_key(key: &[u8; 32]) -> bool {
    // Public-input validation only: a fixed, non-secret clamped scalar maps
    // low-order X25519 points to zero, including non-canonical encodings.
    x25519_dalek::x25519([0x42; 32], *key) != [0; 32]
}

#[derive(Clone, Copy)]
pub(crate) enum Role {
    Initiator,
    Responder,
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Self::Initiator => 0,
            Self::Responder => 1,
        }
    }
    fn peer(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

#[derive(Clone)]
struct Context {
    session_id: [u8; 16],
    initiator_identity: [u8; 32],
    responder_identity: [u8; 32],
}

impl Context {
    fn prologue(&self) -> Vec<u8> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend_from_slice(&self.session_id);
        // Ordered identity slots bind roles as well as both identities.
        bytes.extend_from_slice(&self.initiator_identity);
        bytes.extend_from_slice(&self.responder_identity);
        bytes
    }
}

pub(crate) struct Handshake {
    state: Option<snow::HandshakeState>,
    expected_peer: [u8; 32],
    context: Context,
    role: Role,
    started: Instant,
    received_ephemeral: bool,
    binding_deadline: Option<Instant>,
}

impl Handshake {
    fn new(
        secret: &[u8; 32],
        expected_peer: [u8; 32],
        context: Context,
        role: Role,
    ) -> Result<Self> {
        if !contributory_key(&expected_peer) {
            return Err(failure());
        }
        let prologue = context.prologue();
        let builder = snow::Builder::new(PATTERN.parse().map_err(|_| failure())?)
            .local_private_key(secret)
            .map_err(|_| failure())?
            .prologue(&prologue)
            .map_err(|_| failure())?;
        let state = match role {
            Role::Initiator => builder.build_initiator(),
            Role::Responder => builder.build_responder(),
        }
        .map_err(|_| failure())?;
        Ok(Self {
            state: Some(state),
            expected_peer,
            context,
            role,
            started: Instant::now(),
            received_ephemeral: false,
            binding_deadline: None,
        })
    }

    pub(crate) fn with_verified_peer(
        secret: &[u8; 32],
        peer: crate::attestation::peer_binding::VerifiedPeer,
        local_identity: [u8; 32],
        session: [u8; 16],
        role: Role,
        now: u64,
    ) -> Result<Self> {
        let (key, identity, deadline) = peer.consume_for(session, role.peer().byte(), now)?;
        let (initiator_identity, responder_identity) = match role {
            Role::Initiator => (local_identity, identity),
            Role::Responder => (identity, local_identity),
        };
        let mut handshake = Self::new(
            secret,
            key,
            Context {
                session_id: session,
                initiator_identity,
                responder_identity,
            },
            role,
        )?;
        handshake.binding_deadline = Some(deadline);
        Ok(handshake)
    }

    fn take(&mut self) -> Result<snow::HandshakeState> {
        let state = self.state.take().ok_or_else(failure)?;
        if self.started.elapsed() >= TIMEOUT
            || self
                .binding_deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(failure());
        }
        Ok(state)
    }

    fn check_peer(&self, state: &snow::HandshakeState) -> Result<()> {
        if let Some(key) = state.get_remote_static() {
            if key != self.expected_peer {
                return Err(failure());
            }
        }
        Ok(())
    }

    pub(crate) fn write(&mut self) -> Result<Vec<u8>> {
        // Any state/protocol error consumes the handshake, with no retry/fallback.
        let mut state = self.take()?;
        let mut message = vec![0; 96];
        let len = state
            .write_message(&[], &mut message)
            .map_err(|_| failure())?;
        self.check_peer(&state)?;
        message.truncate(len);
        self.state = Some(state);
        Ok(message)
    }

    pub(crate) fn read(&mut self, message: &[u8]) -> Result<()> {
        let mut state = self.take()?;
        if message.len() > 96 {
            return Err(failure());
        }
        // Both XX roles receive the peer ephemeral in the first 32 bytes of
        // their first incoming message. Snow's default resolver does not reject
        // zero DH outputs, so reject low-order public inputs before processing.
        if !self.received_ephemeral {
            let key: &[u8; 32] = message
                .get(..32)
                .ok_or_else(failure)?
                .try_into()
                .map_err(|_| failure())?;
            if !contributory_key(key) {
                return Err(failure());
            }
            self.received_ephemeral = true;
        }
        // No application data or certificates accepted as unverified early data.
        let len = state
            .read_message(message, &mut [])
            .map_err(|_| failure())?;
        if len != 0 {
            return Err(failure());
        }
        self.check_peer(&state)?;
        self.state = Some(state);
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<Channel> {
        let mut state = self.take()?;
        if !state.is_handshake_finished()
            || state.get_remote_static() != Some(&self.expected_peer[..])
        {
            return Err(failure());
        }
        let mut info = self.context.prologue();
        info.extend_from_slice(state.get_handshake_hash());
        // Sole raw-split call, after completed XX + pin validation. Consuming self
        // ensures these keys cannot also be used by a Noise TransportState.
        let (first, second) = state.dangerously_get_raw_split();
        let first = Zeroizing::new(first);
        let second = Zeroizing::new(second);
        let derive = |input: &[u8], role: Role| -> Result<Zeroizing<[u8; 32]>> {
            let mut info = info.clone();
            info.push(role.byte());
            let mut key = Zeroizing::new([0; 32]);
            Hkdf::<Sha256>::new(Some(DOMAIN), input)
                .expand(&info, &mut *key)
                .map_err(|_| failure())?;
            Ok(key)
        };
        let outbound = derive(&*first, Role::Initiator)?;
        let inbound = derive(&*second, Role::Responder)?;
        let keys = match self.role {
            Role::Initiator => (outbound, inbound),
            Role::Responder => (inbound, outbound),
        };
        Ok(Channel {
            keys: Some(keys),
            context: self.context.clone(),
            role: self.role,
            send: 0,
            receive: 0,
            last_activity: Instant::now(),
            binding_deadline: self.binding_deadline,
        })
    }
}

pub(crate) struct Channel {
    keys: Option<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)>,
    context: Context,
    role: Role,
    send: u64,
    receive: u64,
    last_activity: Instant,
    binding_deadline: Option<Instant>,
}

impl Channel {
    fn header(&self, role: Role, kind: u8, sequence: u64, len: usize) -> Vec<u8> {
        let mut header = b"SABL".to_vec();
        header.push(1);
        header.extend_from_slice(&self.context.session_id);
        header.push(role.byte());
        header.push(kind);
        header.extend_from_slice(&sequence.to_be_bytes());
        header.extend_from_slice(&(len as u32).to_be_bytes());
        header
    }

    fn nonce(sequence: u64) -> [u8; 12] {
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        nonce
    }

    pub(crate) fn seal(&mut self, kind: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        let keys = self.keys.take().ok_or_else(failure)?;
        if self.last_activity.elapsed() >= TIMEOUT
            || self
                .binding_deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            || plaintext.len() > MAX_PAYLOAD
            || self.send == u64::MAX
        {
            return Err(failure());
        }
        let mut record = self.header(self.role, kind, self.send, plaintext.len());
        let cipher = ChaCha20Poly1305::new_from_slice(&*keys.0).map_err(|_| failure())?;
        let ciphertext = cipher
            .encrypt(
                (&Self::nonce(self.send)).into(),
                Payload {
                    msg: plaintext,
                    aad: &record,
                },
            )
            .map_err(|_| failure())?;
        record.extend_from_slice(&ciphertext);
        self.send += 1;
        self.last_activity = Instant::now();
        self.keys = Some(keys);
        Ok(record)
    }

    pub(crate) fn open(&mut self, expected_kind: u8, record: &[u8]) -> Result<Vec<u8>> {
        let keys = self.keys.take().ok_or_else(failure)?;
        if self.last_activity.elapsed() >= TIMEOUT
            || self
                .binding_deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            || self.receive == u64::MAX
            || record.len() < HEADER_LEN + 16
            || record.len() > HEADER_LEN + MAX_PAYLOAD + 16
        {
            return Err(failure());
        }
        let header = self.header(
            self.role.peer(),
            expected_kind,
            self.receive,
            record.len() - HEADER_LEN - 16,
        );
        if record[..HEADER_LEN] != header {
            return Err(failure());
        }
        let cipher = ChaCha20Poly1305::new_from_slice(&*keys.1).map_err(|_| failure())?;
        let plaintext = cipher
            .decrypt(
                (&Self::nonce(self.receive)).into(),
                Payload {
                    msg: &record[HEADER_LEN..],
                    aad: &header,
                },
            )
            .map_err(|_| failure())?;
        self.receive += 1;
        self.last_activity = Instant::now();
        self.keys = Some(keys);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Handshake, Handshake) {
        pair_with_context_change(None)
    }

    fn pair_with_context_change(change: Option<usize>) -> (Handshake, Handshake) {
        let builder = snow::Builder::new(PATTERN.parse().unwrap());
        let a = builder.generate_keypair().unwrap();
        let b = builder.generate_keypair().unwrap();
        pair_with_keys(&a, &b, change)
    }

    fn pair_with_keys(
        a: &snow::Keypair,
        b: &snow::Keypair,
        change: Option<usize>,
    ) -> (Handshake, Handshake) {
        let context = Context {
            session_id: [1; 16],
            initiator_identity: [2; 32],
            responder_identity: [3; 32],
        };
        let mut peer_context = context.clone();
        match change {
            Some(0) => peer_context.session_id[0] ^= 1,
            Some(1) => peer_context.initiator_identity[0] ^= 1,
            Some(2) => peer_context.responder_identity[0] ^= 1,
            _ => (),
        }
        (
            Handshake::new(
                a.private.as_slice().try_into().unwrap(),
                b.public.as_slice().try_into().unwrap(),
                context.clone(),
                Role::Initiator,
            )
            .unwrap(),
            Handshake::new(
                b.private.as_slice().try_into().unwrap(),
                a.public.as_slice().try_into().unwrap(),
                peer_context,
                Role::Responder,
            )
            .unwrap(),
        )
    }

    fn complete(mut a: Handshake, mut b: Handshake) -> (Channel, Channel) {
        b.read(&a.write().unwrap()).unwrap();
        a.read(&b.write().unwrap()).unwrap();
        b.read(&a.write().unwrap()).unwrap();
        (a.finish().unwrap(), b.finish().unwrap())
    }

    #[test]
    fn mutual_authentication_and_bidirectional_counters() {
        let (a, b) = pair();
        let (mut a, mut b) = complete(a, b);
        assert_eq!(*a.keys.as_ref().unwrap().0, *b.keys.as_ref().unwrap().1);
        assert_ne!(*a.keys.as_ref().unwrap().0, *a.keys.as_ref().unwrap().1);
        for _ in 0..3 {
            let record = a.seal(1, b"proof").unwrap();
            assert_eq!(b.open(1, &record).unwrap(), b"proof");
            let record = b.seal(2, b"result").unwrap();
            assert_eq!(a.open(2, &record).unwrap(), b"result");
        }
        assert_eq!((a.send, a.receive, b.send, b.receive), (3, 3, 3, 3));
    }

    #[test]
    fn substituted_static_keys_fail_on_both_roles() {
        for initiator in [true, false] {
            let (mut a, mut b) = pair();
            if initiator {
                a.expected_peer = [9; 32];
            } else {
                b.expected_peer = [9; 32];
            }
            b.read(&a.write().unwrap()).unwrap();
            let second = b.write().unwrap();
            if initiator {
                assert!(a.read(&second).is_err());
                assert!(a.write().is_err());
                assert!(a.finish().is_err());
            } else {
                a.read(&second).unwrap();
                assert!(b.read(&a.write().unwrap()).is_err());
                assert!(b.finish().is_err());
            }
        }
    }

    #[test]
    fn incomplete_out_of_order_and_expired_handshakes_fail_closed() {
        let (a, _) = pair();
        assert!(a.finish().is_err());
        let (_, mut b) = pair();
        assert!(b.write().is_err());
        assert!(b.read(&[0; 32]).is_err());
        let (mut a, _) = pair();
        a.started -= TIMEOUT;
        assert!(a.write().is_err());
        assert!(a.state.is_none());
    }

    #[test]
    fn malformed_and_oversized_handshakes_are_terminal() {
        for message in [vec![], vec![0; 31], vec![0; 97]] {
            let (_, mut b) = pair();
            assert!(b.read(&message).is_err());
            assert!(b.state.is_none());
        }
        let (mut a, mut b) = pair();
        b.read(&a.write().unwrap()).unwrap();
        let mut second = b.write().unwrap();
        second[40] ^= 1;
        assert!(a.read(&second).is_err());
        assert!(a.finish().is_err());
    }

    #[test]
    fn low_order_ephemeral_key_cannot_complete_exchange() {
        for first_byte in [0, 1] {
            let (mut a, mut b) = pair();
            let mut low_order = [0; 32];
            low_order[0] = first_byte;
            assert!(b.read(&low_order).is_err());
            assert!(b.write().is_err());
            assert!(b.finish().is_err());
            a.write().unwrap();
            let mut second = [0; 96];
            second[..32].copy_from_slice(&low_order);
            assert!(a.read(&second).is_err());
            assert!(a.finish().is_err());
        }
    }

    #[test]
    fn session_and_ordered_identity_context_are_bound_to_handshake() {
        for field in 0..3 {
            let (mut a, mut b) = pair_with_context_change(Some(field));
            b.read(&a.write().unwrap()).unwrap();
            assert!(
                a.read(&b.write().unwrap()).is_err(),
                "context field {field}"
            );
            assert!(a.finish().is_err());
        }
    }

    #[test]
    fn final_handshake_message_tampering_is_rejected() {
        let (mut a, mut b) = pair();
        b.read(&a.write().unwrap()).unwrap();
        a.read(&b.write().unwrap()).unwrap();
        let mut third = a.write().unwrap();
        third[40] ^= 1;
        assert!(b.read(&third).is_err());
        assert!(b.finish().is_err());
    }

    #[test]
    fn every_header_field_and_ciphertext_are_authenticated() {
        for offset in [0, 4, 5, 21, 22, 23, 31, HEADER_LEN, HEADER_LEN + 16] {
            let (a, b) = pair();
            let (mut a, mut b) = complete(a, b);
            let mut record = a.seal(1, b"proof").unwrap();
            record[offset] ^= 1;
            assert!(b.open(1, &record).is_err(), "offset {offset}");
            assert!(b.keys.is_none());
        }
    }

    #[test]
    fn replay_reflection_reordering_and_wrong_message_type_fail() {
        for attack in 0..4 {
            let (a, b) = pair();
            let (mut a, mut b) = complete(a, b);
            let first = a.seal(1, b"proof").unwrap();
            match attack {
                0 => {
                    b.open(1, &first).unwrap();
                    assert!(b.open(1, &first).is_err());
                }
                1 => assert!(a.open(1, &first).is_err()),
                2 => {
                    let next = a.seal(1, b"next").unwrap();
                    assert!(b.open(1, &next).is_err());
                }
                _ => assert!(b.open(2, &first).is_err()),
            }
        }
    }

    #[test]
    fn session_keys_are_fresh_even_with_same_static_keys_and_context() {
        let builder = snow::Builder::new(PATTERN.parse().unwrap());
        let first = builder.generate_keypair().unwrap();
        let second = builder.generate_keypair().unwrap();
        let (a, b) = pair_with_keys(&first, &second, None);
        let (mut a, _) = complete(a, b);
        let (c, d) = pair_with_keys(&first, &second, None);
        let (_, mut d) = complete(c, d);
        assert!(d.open(1, &a.seal(1, b"proof").unwrap()).is_err());
    }

    #[test]
    fn record_header_is_aead_associated_data() {
        let (a, b) = pair();
        let (mut a, b) = complete(a, b);
        let record = a.seal(1, b"proof").unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(&*b.keys.as_ref().unwrap().1).unwrap();
        let mut header = record[..HEADER_LEN].to_vec();
        assert!(cipher
            .decrypt(
                (&Channel::nonce(0)).into(),
                Payload {
                    msg: &record[HEADER_LEN..],
                    aad: &header
                }
            )
            .is_ok());
        header[22] ^= 1;
        assert!(cipher
            .decrypt(
                (&Channel::nonce(0)).into(),
                Payload {
                    msg: &record[HEADER_LEN..],
                    aad: &header
                }
            )
            .is_err());
    }

    #[test]
    fn empty_and_maximum_payloads_round_trip_and_truncation_fails() {
        let (a, b) = pair();
        let (mut a, mut b) = complete(a, b);
        for payload in [vec![], vec![5; MAX_PAYLOAD]] {
            let record = a.seal(1, &payload).unwrap();
            assert_eq!(record.len(), HEADER_LEN + payload.len() + 16);
            assert_eq!(b.open(1, &record).unwrap(), payload);
        }
        let record = a.seal(1, b"proof").unwrap();
        assert!(b.open(1, &record[..record.len() - 1]).is_err());
        assert!(b.keys.is_none());
    }

    #[test]
    fn counters_timeouts_and_size_limits_fail_closed() {
        for case in 0..5 {
            let (a, b) = pair();
            let (mut a, mut b) = complete(a, b);
            match case {
                0 => {
                    a.send = u64::MAX;
                    assert!(a.seal(1, b"").is_err());
                    assert!(a.keys.is_none());
                }
                1 => {
                    b.receive = u64::MAX;
                    assert!(b.open(1, &a.seal(1, b"").unwrap()).is_err());
                }
                2 => {
                    a.last_activity -= TIMEOUT;
                    assert!(a.seal(1, b"").is_err());
                }
                3 => {
                    assert!(a.seal(1, &vec![0; MAX_PAYLOAD + 1]).is_err());
                }
                _ => {
                    b.last_activity -= TIMEOUT;
                    assert!(b.open(1, &a.seal(1, b"").unwrap()).is_err());
                }
            }
        }
    }

    #[test]
    fn binding_deadline_limits_handshake_and_active_channel() {
        let (mut a, _) = pair();
        a.binding_deadline = Some(Instant::now());
        assert!(a.write().is_err());
        assert!(a.state.is_none());
        for send in [true, false] {
            let (mut a, mut b) = pair();
            let deadline = Instant::now() + Duration::from_secs(10);
            a.binding_deadline = Some(deadline);
            b.binding_deadline = Some(deadline);
            let (mut a, mut b) = complete(a, b);
            assert_eq!(a.binding_deadline, Some(deadline));
            assert_eq!(b.binding_deadline, Some(deadline));
            if send {
                a.binding_deadline = Some(Instant::now());
                assert!(a.seal(1, b"proof").is_err());
                assert!(a.keys.is_none());
            } else {
                let record = a.seal(1, b"proof").unwrap();
                b.binding_deadline = Some(Instant::now());
                assert!(b.open(1, &record).is_err());
                assert!(b.keys.is_none());
            }
        }
    }
}
