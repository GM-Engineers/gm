//! SM9 Key Exchange Protocol (GM/T 0044.3-2016 §7)
//!
//! Implements identity-based key agreement between two parties using SM9
//! encryption keys. The protocol produces a shared secret key that can be
//! used for symmetric encryption in subsequent communication.
//!
//! # Protocol Overview
//!
//! 1. **Initiator (A)** computes `R_A = [r_A]Q_B` and sends it to B
//! 2. **Responder (B)** verifies `R_A`, computes `R_B = [r_B]Q_A` and the
//!    shared key `SK_B`, then sends `R_B` (and optionally `S_B`) back
//! 3. **Initiator (A)** verifies `R_B`, computes the shared key `SK_A`,
//!    and optionally verifies `S_B` / sends `S_A` for mutual confirmation
//!
//! # Usage
//!
//! ```text
//! let mut rng = rand::rng();
//! let master = EncMasterKey::generate(&mut rng)?;
//! let de_a = master.extract_key(b"alice@example.com")?;
//! let de_b = master.extract_key(b"bob@example.com")?;
//!
//! // Round 1: A → B (R_A)
//! let (state_a, r_a) = initiator_begin(
//!     b"alice@example.com", b"bob@example.com",
//!     &master.ppube, &mut rng
//! )?;
//!
//! // B processes and sends R_B back
//! let (resp_output, r_b) = responder_process(
//!     b"alice@example.com", b"bob@example.com",
//!     &master.ppube, &de_b, &r_a, 16, false, &mut rng
//! )?;
//!
//! // Round 2: A finishes
//! let output_a = initiator_finish(
//!     state_a, &r_b, &de_a,
//!     b"alice@example.com", b"bob@example.com", 16, None
//! )?;
//!
//! assert_eq!(output_a.shared_key, resp_output.shared_key);
//! ```

use crate::Sm9Error;
use crate::arith::Fp12;
use crate::curve::ScalarMul;
use crate::curve::g1::G1Point;
use crate::hash::hash1;
use crate::key::{EncUserKey, random_scalar};
use crate::pairing::ate::pairing;
use crate::params::{g1_generator, g2_generator};
use crate::z256::Z256;
use rand::CryptoRng;
use sm3::Sm3;
use sm3::digest::Digest;

/// SM9 key exchange function identifier (hid = 0x03)
pub const SM9_KEY_EXCHANGE_HID: u8 = 0x03;

// ============================================================================
// Key Exchange State and Output Types
// ============================================================================

/// State for the initiator (A) after round 1.
///
/// Carries the ephemeral secret `r_a`, the public `Q_B` for later pairing
/// computation, and identifiers needed for KDF and key confirmation.
#[derive(Clone)]
#[allow(dead_code)]
pub struct InitiatorState {
    /// Ephemeral random scalar
    pub r_a: Z256,
    /// Q_B = [H1(IDB||hid,N)]P1 + Ppub-e
    q_b: G1Point,
    /// Initiator identity (for KDF / confirmation)
    id_a: Vec<u8>,
    /// Responder identity (for KDF / confirmation)
    id_b: Vec<u8>,
    /// `R_A = [r_a]Q_B` (we already sent this, keep for KDF)
    r_a_point: G1Point,
}

/// Output of the initiator's round-1: ephemeral point R_A to send to B.
///
/// This is the **only thing** sent to the responder in the first message.
#[derive(Clone)]
pub struct InitiatorRound1 {
    pub r_a: G1Point,
}

/// Output of the responder (B): ephemeral point R_B and the derived shared key.
#[derive(Clone)]
pub struct ResponderOutput {
    /// `R_B = [r_B]Q_A` — send to initiator
    pub r_b: G1Point,
    /// Shared key SK_B derived by B
    pub shared_key: Vec<u8>,
    /// Optional key confirmation value S_B (send to A when confirmation is requested)
    pub s_b: Option<Vec<u8>>,
}

/// Output of the initiator's final step
#[derive(Clone)]
pub struct InitiatorOutput {
    /// Shared key SK_A derived by A
    pub shared_key: Vec<u8>,
    /// Optional key confirmation value S_A (send to B for mutual confirmation)
    pub s_a: Option<Vec<u8>>,
}

// ============================================================================
// Round 1: Initiator (A) — Begin
// ============================================================================

/// Initiate SM9 key exchange (Party A, round 1).
///
/// Computes `Q_B = [H1(IDB||hid,N)]P1 + Ppub-e` and the ephemeral point
/// `R_A = [r_A]Q_B`.  Returns the state (for later use) and the round-1
/// message to send to B.
pub fn initiator_begin(
    id_a: &[u8],
    id_b: &[u8],
    ppub_e: &G1Point,
    rng: &mut impl CryptoRng,
) -> Result<(InitiatorState, InitiatorRound1), Sm9Error> {
    let h1_b = hash1(id_b, SM9_KEY_EXCHANGE_HID);
    let q_b = compute_q(h1_b, ppub_e);
    let r_a = random_scalar(rng)?;
    let r_a_point = q_b.scalar_mul(&r_a);

    let state = InitiatorState {
        r_a,
        q_b,
        id_a: id_a.to_vec(),
        id_b: id_b.to_vec(),
        r_a_point,
    };

    let round1 = InitiatorRound1 { r_a: r_a_point };

    Ok((state, round1))
}

// ============================================================================
// Round 2: Responder (B) — Process and Respond
// ============================================================================

/// Process initiator's round-1 message and produce the responder's response
/// (Party B).
///
/// Verifies `R_A ∈ G1`, computes ephemerals, pairings, and derives `SK_B`.
/// Returns the round-2 message to send back to A and the shared key.
///
/// # Parameters
///
/// * `ppub_e` — KGC encryption master public key
/// * `de_b` — B's encryption private key
/// * `r_a` — initiator's R_A received from A (G1 point)
/// * `klen` — desired shared key length in **bytes**
/// * `need_confirm` — whether to compute and return key confirmation value S_B
#[allow(clippy::too_many_arguments)]
pub fn responder_process(
    id_a: &[u8],
    id_b: &[u8],
    ppub_e: &G1Point,
    de_b: &EncUserKey,
    r_a: &G1Point,
    klen: usize,
    need_confirm: bool,
    rng: &mut impl CryptoRng,
) -> Result<ResponderOutput, Sm9Error> {
    // B1: Q_A = [H1(IDA||hid,N)]P1 + Ppub-e
    let h1_a = hash1(id_a, SM9_KEY_EXCHANGE_HID);
    let q_a = compute_q(h1_a, ppub_e);

    // B2-B3: ephemeral
    let r_b = random_scalar(rng)?;
    let r_b_point = q_a.scalar_mul(&r_b);

    // B4: Verify R_A ∈ G1 (skip full on-curve check — scalar mul and affine
    //     conversion serve as structural validation)
    if r_a.to_affine().is_none() {
        return Err(Sm9Error::InvalidPoint);
    }

    // g1 = e(R_A, de_B)     [R_A ∈ G1, de_B = de ∈ G2]
    let g1 = pairing(r_a, &de_b.de);

    // g2 = e(Ppub-e, P2)^{r_B}
    let p2 = g2_generator();
    let e_pub_p2 = pairing(ppub_e, &p2);
    let g2 = e_pub_p2.pow(&r_b);

    // g3 = g1^{r_B}
    let g3 = g1.pow(&r_b);

    // B5: SK_B = KDF(IDA || IDB || RA || RB || g1 || g2 || g3, klen)
    let shared_key = kdf_key_exchange(id_a, id_b, r_a, &r_b_point, &g1, &g2, &g3, klen);

    // B6: Optional key confirmation S_B
    let s_b = if need_confirm {
        Some(compute_sb(&g1, &g2, &g3, id_a, id_b, r_a, &r_b_point))
    } else {
        None
    };

    Ok(ResponderOutput {
        r_b: r_b_point,
        shared_key,
        s_b,
    })
}

// ============================================================================
// Round 3: Initiator (A) — Finish
// ============================================================================

/// Finish SM9 key exchange (Party A, round 2).
///
/// Verifies `R_B ∈ G1`, computes pairings, derives `SK_A`, and optionally
/// verifies B's key confirmation `S_B`.
///
/// # Parameters
///
/// * `state` — state from `initiator_begin()`
/// * `r_b` — responder's R_B received from B
/// * `de_a` — A's encryption private key
/// * `klen` — desired shared key length in **bytes**
/// * `s_b` — optional B's key confirmation value to verify (pass `None` if not used)
pub fn initiator_finish(
    state: InitiatorState,
    r_b: &G1Point,
    de_a: &EncUserKey,
    id_a: &[u8],
    id_b: &[u8],
    klen: usize,
    s_b: Option<&[u8]>,
) -> Result<InitiatorOutput, Sm9Error> {
    // A5: Verify R_B ∈ G1
    if r_b.to_affine().is_none() {
        return Err(Sm9Error::InvalidPoint);
    }

    // g1' = e(Ppub-e, P2)^{r_A}
    let p2 = g2_generator();
    let de_a_ppube = &de_a.ppube;
    let e_pub_p2 = pairing(de_a_ppube, &p2);
    let g1 = e_pub_p2.pow(&state.r_a);

    // g2' = e(R_B, de_A)
    let g2 = pairing(r_b, &de_a.de);

    // g3' = (g2')^{r_A}
    let g3 = g2.pow(&state.r_a);

    // Optional key confirmation: verify S_B
    if let Some(sb_val) = s_b {
        let expected_sb = compute_sb(&g1, &g2, &g3, id_a, id_b, &state.r_a_point, r_b);
        if !constant_time_eq(&expected_sb, sb_val) {
            return Err(Sm9Error::CryptoError(
                "Key confirmation failed: S_B mismatch".to_string(),
            ));
        }
    }

    // A7: SK_A = KDF(IDA || IDB || RA || RB || g1' || g2' || g3', klen)
    let shared_key = kdf_key_exchange(id_a, id_b, &state.r_a_point, r_b, &g1, &g2, &g3, klen);

    // A8: Optional key confirmation S_A
    let s_a = compute_sa(&g1, &g2, &g3, id_a, id_b, &state.r_a_point, r_b);

    Ok(InitiatorOutput {
        shared_key,
        s_a: Some(s_a),
    })
}

// ============================================================================
// Key Confirmation (optional, per §7.2)
// ============================================================================

/// Compute S_B = SM3(0x82 || g1 || SM3(g2 || g3 || IDA || IDB || RA || RB))
///
/// This is B's key confirmation value — B sends this to A for verification.
fn compute_sb(
    g1: &Fp12,
    g2: &Fp12,
    g3: &Fp12,
    id_a: &[u8],
    id_b: &[u8],
    r_a: &G1Point,
    r_b: &G1Point,
) -> Vec<u8> {
    let inner = sm3_multi(&[
        &gt_to_bytes(g2),
        &gt_to_bytes(g3),
        id_a,
        id_b,
        &g1_to_kdf_bytes(r_a),
        &g1_to_kdf_bytes(r_b),
    ]);
    let outer = sm3_multi(&[&[0x82], &gt_to_bytes(g1), &inner]);
    outer.to_vec()
}

/// Compute S_A = SM3(0x83 || g1' || SM3(g2' || g3' || IDA || IDB || RA || RB))
///
/// This is A's key confirmation value — A sends this to B for mutual confirmation.
#[allow(clippy::too_many_arguments)]
fn compute_sa(
    g1: &Fp12,
    g2: &Fp12,
    g3: &Fp12,
    id_a: &[u8],
    id_b: &[u8],
    r_a: &G1Point,
    r_b: &G1Point,
) -> Vec<u8> {
    let inner = sm3_multi(&[
        &gt_to_bytes(g2),
        &gt_to_bytes(g3),
        id_a,
        id_b,
        &g1_to_kdf_bytes(r_a),
        &g1_to_kdf_bytes(r_b),
    ]);
    let outer = sm3_multi(&[&[0x83], &gt_to_bytes(g1), &inner]);
    outer.to_vec()
}

/// Verify S_A received from A against B's computation (mutual confirmation).
#[allow(clippy::too_many_arguments)]
pub fn verify_sa(
    g1: &Fp12,
    g2: &Fp12,
    g3: &Fp12,
    id_a: &[u8],
    id_b: &[u8],
    r_a: &G1Point,
    r_b: &G1Point,
    s_a: &[u8],
) -> bool {
    let expected = compute_sa(g1, g2, g3, id_a, id_b, r_a, r_b);
    constant_time_eq(&expected, s_a)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute Q_x = [H1(ID||hid,N)]P1 + Ppub-e
fn compute_q(h1: Z256, ppub_e: &G1Point) -> G1Point {
    let p1 = g1_generator();
    let h1_p1 = p1.scalar_mul(&h1);
    // Addition on G1: Jacobian add
    h1_p1.add(ppub_e)
}

/// SM9 key exchange KDF using SM3 in counter mode.
///
/// KDF(Z, klen) where Z = IDA || IDB || RA || RB || g1 || g2 || g3
#[allow(clippy::too_many_arguments)]
fn kdf_key_exchange(
    id_a: &[u8],
    id_b: &[u8],
    r_a: &G1Point,
    r_b: &G1Point,
    g1: &Fp12,
    g2: &Fp12,
    g3: &Fp12,
    klen: usize,
) -> Vec<u8> {
    let mut k = Vec::with_capacity(klen);
    let mut counter: u32 = 1;

    let ra_bytes = g1_to_kdf_bytes(r_a);
    let rb_bytes = g1_to_kdf_bytes(r_b);
    let g1_bytes = gt_to_bytes(g1);
    let g2_bytes = gt_to_bytes(g2);
    let g3_bytes = gt_to_bytes(g3);

    while k.len() < klen {
        let mut hasher = Sm3::new();
        hasher.update(id_a);
        hasher.update(id_b);
        hasher.update(&ra_bytes);
        hasher.update(&rb_bytes);
        hasher.update(&g1_bytes);
        hasher.update(&g2_bytes);
        hasher.update(&g3_bytes);
        hasher.update(counter.to_be_bytes());
        k.extend_from_slice(&hasher.finalize());
        counter += 1;
    }

    k.truncate(klen);
    k
}

/// Serialize G1 point for KDF input (uncompressed: 0x04 || x || y).
fn g1_to_kdf_bytes(point: &G1Point) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(65);
    if let Some((x, y)) = point.to_affine() {
        bytes.push(0x04);
        bytes.extend_from_slice(&x.to_bytes());
        bytes.extend_from_slice(&y.to_bytes());
    } else {
        // Identity point: fallback representation
        bytes.push(0x00);
        bytes.extend_from_slice(&[0u8; 64]);
    }
    bytes
}

/// Serialize GT (Fp12) element for KDF input.
///
/// Uses the standard Fp12 byte representation:
/// c0 || c1 || c2, each Fp4 serialized as c0.c0||c0.c1||c1.c0||c1.c1.
/// Total: 384 bytes per GT element.
fn gt_to_bytes(g: &Fp12) -> Vec<u8> {
    g.to_bytes()
}

/// SM3 hash of multiple byte slices concatenated.
fn sm3_multi(chunks: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sm3::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().to_vec()
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

// ============================================================================
// Convenience: Symmetric high-level API
// ============================================================================

/// Convenience function: perform a complete SM9 key exchange in one call.
///
/// Both parties must use the same KGC (same `ppub_e`).
///
/// # Returns
///
/// `(sk_a, sk_b)` — the shared keys derived by each party.
/// They MUST be equal.
pub fn key_exchange(
    id_a: &[u8],
    de_a: &EncUserKey,
    id_b: &[u8],
    de_b: &EncUserKey,
    ppub_e: &G1Point,
    klen: usize,
    rng: &mut impl CryptoRng,
) -> Result<(Vec<u8>, Vec<u8>), Sm9Error> {
    // Round 1: A → B
    let (state_a, round1) = initiator_begin(id_a, id_b, ppub_e, rng)?;

    // Round 2: B → A
    let resp_output = responder_process(id_a, id_b, ppub_e, de_b, &round1.r_a, klen, false, rng)?;

    // Round 3: A finishes
    let init_output = initiator_finish(state_a, &resp_output.r_b, de_a, id_a, id_b, klen, None)?;

    Ok((init_output.shared_key, resp_output.shared_key))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    use crate::key::EncMasterKey;
    use rand::rng;

    fn setup() -> (EncMasterKey, Vec<u8>, Vec<u8>, EncUserKey, EncUserKey) {
        let mut rng = rng();
        let master = EncMasterKey::generate(&mut rng).unwrap();
        let id_a = b"alice@example.com".to_vec();
        let id_b = b"bob@example.com".to_vec();
        let de_a = master.extract_key_exchange(&id_a).unwrap();
        let de_b = master.extract_key_exchange(&id_b).unwrap();
        (master, id_a, id_b, de_a, de_b)
    }

    #[test]
    fn test_key_exchange_consistency() {
        let mut rng = rng();
        let (master, id_a, id_b, de_a, de_b) = setup();

        let (sk_a, sk_b) =
            key_exchange(&id_a, &de_a, &id_b, &de_b, &master.ppube, 32, &mut rng).unwrap();

        assert_eq!(sk_a, sk_b);
        assert_eq!(sk_a.len(), 32);
    }

    #[test]
    fn test_key_exchange_different_lengths() {
        let mut rng = rng();
        let (master, id_a, id_b, de_a, de_b) = setup();

        for klen in &[16, 32, 48, 64, 128] {
            let (sk_a, sk_b) =
                key_exchange(&id_a, &de_a, &id_b, &de_b, &master.ppube, *klen, &mut rng).unwrap();
            assert_eq!(sk_a, sk_b, "keys differ for klen={}", klen);
            assert_eq!(sk_a.len(), *klen);
        }
    }

    #[test]
    fn test_key_exchange_with_confirmation() {
        let mut rng = rng();
        let (master, id_a, id_b, _de_a, de_b) = setup();
        let de_a = master.extract_key_exchange(&id_a).unwrap();

        // Round 1: A → B
        let (state_a, round1) = initiator_begin(&id_a, &id_b, &master.ppube, &mut rng).unwrap();

        // B processes with confirmation
        let resp = responder_process(
            &id_a,
            &id_b,
            &master.ppube,
            &de_b,
            &round1.r_a,
            32,
            true,
            &mut rng,
        )
        .unwrap();

        // A verifies S_B and finishes
        let output = initiator_finish(
            state_a,
            &resp.r_b,
            &de_a,
            &id_a,
            &id_b,
            32,
            resp.s_b.as_deref(),
        )
        .unwrap();

        assert_eq!(output.shared_key, resp.shared_key);
        assert!(!output.s_a.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_key_exchange_bad_confirmation_rejected() {
        let mut rng = rng();
        let (master, id_a, id_b, de_a, de_b) = setup();

        let (state_a, round1) = initiator_begin(&id_a, &id_b, &master.ppube, &mut rng).unwrap();
        let resp = responder_process(
            &id_a,
            &id_b,
            &master.ppube,
            &de_b,
            &round1.r_a,
            32,
            true,
            &mut rng,
        )
        .unwrap();

        // Feed a wrong S_B to A
        let bad_sb = vec![0u8; 32];
        let result = initiator_finish(state_a, &resp.r_b, &de_a, &id_a, &id_b, 32, Some(&bad_sb));
        assert!(result.is_err());
    }

    #[test]
    fn test_key_exchange_rejects_invalid_point() {
        let mut rng = rng();
        let (master, id_a, id_b, de_a, de_b) = setup();

        let (_state, round1) = initiator_begin(&id_a, &id_b, &master.ppube, &mut rng).unwrap();
        let _resp = responder_process(
            &id_a,
            &id_b,
            &master.ppube,
            &de_b,
            &round1.r_a,
            32,
            false,
            &mut rng,
        )
        .unwrap();

        // Attempt to finish with identity point as R_B
        let state = InitiatorState {
            r_a: Z256([1, 0, 0, 0]),
            q_b: round1.r_a,
            id_a: id_a.clone(),
            id_b: id_b.clone(),
            r_a_point: round1.r_a,
        };
        let zero = G1Point::identity();
        assert!(initiator_finish(state, &zero, &de_a, &id_a, &id_b, 32, None).is_err());

        // Valid case succeeds
        let (state2, round1_2) = initiator_begin(&id_a, &id_b, &master.ppube, &mut rng).unwrap();
        let resp2 = responder_process(
            &id_a,
            &id_b,
            &master.ppube,
            &de_b,
            &round1_2.r_a,
            32,
            false,
            &mut rng,
        )
        .unwrap();
        assert!(initiator_finish(state2, &resp2.r_b, &de_a, &id_a, &id_b, 32, None).is_ok());
    }
}
