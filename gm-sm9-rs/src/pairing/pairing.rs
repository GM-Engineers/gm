//! Bilinear pairing for SM9
//!
//! Implements the R-ate pairing e: G1 × G2 → GT
//! where GT is the subgroup of Fp12 of order N.
//!
//! Based on GmSSL implementation (guanzhi/GmSSL).

use crate::pairing::curve::{g1::G1Point, g2::G2Point, Identity};
use crate::arith::z256::Z256;
use crate::arith::{FieldElement, Fp, Fp12, Fp2, Fp4};

/// R-ate pairing parameter for SM9 (from GmSSL)
/// This is the binary expansion of the R-ate parameter
const RATE_ABITS: &str = "00100000000000000000000000000000000000010000101100020200101000020";

/// Compute the R-ate pairing e(P, Q)
///
/// P is in G1, Q is in G2
pub fn pairing(p: &G1Point, q: &G2Point) -> Fp12 {
    // Miller loop
    let f = miller_loop(p, q);

    // Final exponentiation
    final_exponentiation(&f)
}

/// Miller loop for R-ate pairing
/// Based on GmSSL's second (non-fractional) sm9_z256_pairing implementation
pub fn miller_loop(p: &G1Point, q: &G2Point) -> Fp12 {
    // Convert P to affine coordinates (GmSSL does sm9_z256_point_to_affine)
    let p_aff = match p.to_affine() {
        Some((x, y)) => (x, y),
        None => return Fp12::ONE, // P is identity
    };

    let mut f = Fp12::ONE;
    let mut t = *q; // Working point in G2, starts as Q

    // Precompute -Q for '2' bits
    let q_neg = q.neg();

    // Precompute values for line_function_add (same as GmSSL's pre array)
    let pre0 = q.y.square();
    let pre4 = q.x.mul(&q.z).double();
    let q_z2 = q.z.square();
    let pre1 = q_z2.mul(&q.z);
    let pre2 = pre1.mul_fp(&p_aff.1).double();
    let pre3 = pre1.mul_fp(&p_aff.0).double().neg();

    // Process each bit of the R-ate parameter
    for ch in RATE_ABITS.chars() {
        // Double step: f = f² * l(t, t, P)
        f = f.square();
        let (lw0, lw1, lw2) = line_function_double_lw(&mut t, &p_aff);
        f = fp12_line_mul(&f, &lw0, &lw1, &lw2);

        match ch {
            '1' => {
                // Add Q
                let (lw0, lw1, lw2) =
                    line_function_add_lw(&mut t, q, &p_aff, &pre0, &pre1, &pre2, &pre3, &pre4);
                f = fp12_line_mul(&f, &lw0, &lw1, &lw2);
            }
            '2' => {
                // Add -Q
                let (lw0, lw1, lw2) = line_function_add_lw_no_pre(&mut t, &q_neg, &p_aff);
                f = fp12_line_mul(&f, &lw0, &lw1, &lw2);
            }
            _ => {} // '0' bit: no addition
        }
    }

    // Final addition steps (Frobenius actions)
    // Q1 = π₁(Q) - Frobenius on twist curve
    // GmSSL: conjugate(X), conjugate(Y), conjugate(Z)*ALPHA1
    let alpha1 = Fp(Z256::new([
        0x1a98dfbd4575299f,
        0x9ec8547b245c54fd,
        0xf51f5eac13df846c,
        0x9ef74015d5a16393,
    ])); // Already Montgomery form
    let q1_x = q.x.frobenius();
    let q1_y = q.y.frobenius();
    let q1_z = q.z.frobenius().mul_fp(&alpha1); // conjugate(Z) * ALPHA1
    let q1 = G2Point::new(q1_x, q1_y, q1_z);

    // Q2 = -π₂(Q) - Negated Frobenius squared on twist curve
    // GmSSL: copy(X), negate(Y), Z*ALPHA2
    let alpha2 = Fp(Z256::new([
        0xb626197dce4736ca,
        0x08296b3557ed0186,
        0x9c705db2fd91512a,
        0x1c753e748601c992,
    ])); // Already Montgomery form
    let q2_x = q.x;
    let q2_y = q.y.neg();
    let q2_z = q.z.mul_fp(&alpha2); // Z * ALPHA2 (no conjugate)
    let q2 = G2Point::new(q2_x, q2_y, q2_z);

    // Add Q1 (using no_pre version since Q1 is not Q)
    let (lw0, lw1, lw2) = line_function_add_lw_no_pre(&mut t, &q1, &p_aff);
    f = fp12_line_mul(&f, &lw0, &lw1, &lw2);

    // Add Q2
    let (lw0, lw1, lw2) = line_function_add_lw_no_pre(&mut t, &q2, &p_aff);
    f = fp12_line_mul(&f, &lw0, &lw1, &lw2);

    f
}

/// Multiply Fp12 by a sparse line function
/// Based on GmSSL's sm9_z256_fp12_line_mul
/// The line function has the form: lw[0] + lw[1]*w^2 + lw[2]*w^3
/// which corresponds to Fp12: (lw[0] + lw[2]*v) + 0*w + (lw[1])*w^2
fn fp12_line_mul(a: &Fp12, lw0: &Fp2, lw1: &Fp2, lw2: &Fp2) -> Fp12 {
    // Construct lw4 = lw[0] + lw[2]*v (Fp4)
    let lw4 = Fp4::new(*lw0, *lw2);

    // r0 = a[0] * lw4
    // r1 = a[1] * lw4
    // r2 = a[2] * lw4
    let mut r0 = a.c0.mul(&lw4);
    let mut r1 = a.c1.mul(&lw4);
    let mut r2 = a.c2.mul(&lw4);

    // Additional terms from lw[1] (w^2 coefficient)
    // r2[0] += a[0][0] * lw[1]
    r2.c0 = r2.c0.add(&a.c0.c0.mul(lw1));
    // r2[1] += a[0][1] * lw[1]
    r2.c1 = r2.c1.add(&a.c0.c1.mul(lw1));
    // r0[1] += a[1][0] * lw[1]
    r0.c1 = r0.c1.add(&a.c1.c0.mul(lw1));
    // r0[0] += a[1][1] * lw[1] * u (mul_u)
    r0.c0 = r0.c0.add(&a.c1.c1.mul_u().mul(lw1));
    // r1[1] += a[2][0] * lw[1]
    r1.c1 = r1.c1.add(&a.c2.c0.mul(lw1));
    // r1[0] += a[2][1] * lw[1] * u (mul_u)
    r1.c0 = r1.c0.add(&a.c2.c1.mul_u().mul(lw1));

    Fp12::new(r0, r1, r2)
}

/// Line function for point doubling: l_{T,T}(P)
/// Based on GmSSL's sm9_z256_eval_g_tangent (second version)
/// Updates T in place to 2*T, returns lw[0], lw[1], lw[2]
/// where g_line = lw[0] + lw[1]*w^2 + lw[2]*w^3
fn line_function_double_lw(t: &mut G2Point, p_aff: &(Fp, Fp)) -> (Fp2, Fp2, Fp2) {
    if t.is_identity() {
        return (Fp2::ZERO, Fp2::ZERO, Fp2::ZERO);
    }

    let x1 = &t.x;
    let y1 = &t.y;
    let z1 = &t.z;

    // T1 = Z1^2
    let t1 = z1.square();
    // A = X1^2
    let a = x1.square();
    // B = Y1^2
    let b = y1.square();
    // C = B^2
    let c = b.square();
    // D = 2*((X1 + B)^2 - A - C)
    let d = x1.add(&b).square().sub(&a).sub(&c).double();
    // Z3 = (Y1 + Z1)^2 - B - T1
    let z3 = y1.add(z1).square().sub(&b).sub(&t1);

    // lw[0] = 4*B + A
    let mut lw0 = b.double().double().add(&a);
    // A = 3*A (tri)
    let a_tri = a.add(&a).add(&a);
    // B = A^2 = 9*A^2
    let b_new = a_tri.square();
    // X3 = B - 2*D
    let x3 = b_new.sub(&d.double());
    // lw[0] = lw[0] + B (= 4B + A + 9A^2)
    lw0 = lw0.add(&b_new);
    // Y3 = (D - X3) * A - 8*C
    let y3 = d.sub(&x3).mul(&a_tri).sub(&c.double().double().double());
    // lw[2] = 2*Z3*T1
    let mut lw2 = z3.mul(&t1).double();
    // lw[1] = -2*A*T1
    let mut lw1 = a_tri.mul(&t1).double().neg();
    // A = (X1 + A_tri)^2
    let a_new = x1.add(&a_tri).square();
    // lw[0] = A - lw[0] = (X1+3A)^2 - (4B+A+9A^2)
    lw0 = a_new.sub(&lw0);

    // Multiply by P's affine coordinates
    // lw[1] *= xQ
    lw1 = lw1.mul_fp(&p_aff.0);
    // lw[2] *= yQ
    lw2 = lw2.mul_fp(&p_aff.1);

    // Update t in place
    *t = G2Point::new(x3, y3, z3);

    (lw0, lw1, lw2)
}

/// Line function for point addition: l_{T,Q}(P) with precomputed values
/// Based on GmSSL's sm9_z256_eval_g_line (second version)
/// Uses precomputed values from Q for efficiency
/// Updates T in place to T+Q, returns lw[0], lw[1], lw[2]
#[allow(clippy::too_many_arguments)]
fn line_function_add_lw(
    t: &mut G2Point,
    q: &G2Point,
    _p_aff: &(Fp, Fp),
    pre0: &Fp2, // Q->Y^2
    pre1: &Fp2, // Q->Z^3
    pre2: &Fp2, // 2*Q->Z^3*yQ
    pre3: &Fp2, // -2*Q->Z^3*xQ
    pre4: &Fp2, // 2*Q->X*Q->Z
) -> (Fp2, Fp2, Fp2) {
    if t.is_identity() || q.is_identity() {
        return (Fp2::ZERO, Fp2::ZERO, Fp2::ZERO);
    }

    let x1 = &t.x;
    let y1 = &t.y;
    let z1 = &t.z;
    let x2 = &q.x;
    let y2 = &q.y;
    let z2 = &q.z;

    // T1 = Z1^2
    let t1 = z1.square();
    // T2 = Z2^2
    let t2 = z2.square();
    // Z3 = (Z1 + Z2)^2 - T1 - T2
    let z3 = z1.add(z2).square().sub(&t1).sub(&t2);
    // A = X1 * T2
    let a = x1.mul(&t2);
    // B = X2 * T1
    let mut b = x2.mul(&t1);
    // C = 2 * Y1 * pre[1] = 2 * Y1 * Q->Z^3
    let c = y1.mul(pre1).double();
    // D = (Y2 + Z1)^2 - pre[0] - T1) * T1
    let d = y2.add(z1).square().sub(pre0).sub(&t1).mul(&t1);

    // B = B - A
    b = b.sub(&a);
    // Z3 = Z3 * B
    let z3 = z3.mul(&b);
    // T1 = (2*B)^2
    let t1 = b.double().square();
    // X3 = B * T1
    let x3 = b.mul(&t1);
    // Y3 = C * X3
    let y3 = c.mul(&x3);
    // A = A * T1
    let a = a.mul(&t1);
    // B = D - C
    let b = d.sub(&c);
    // T2 = 2*A
    let t2 = a.double();
    // X3 = X3 + T2
    let x3 = x3.add(&t2);
    // T2 = B^2
    let t2 = b.square();
    // X3 = T2 - X3
    let x3 = t2.sub(&x3);
    // T2 = A - X3
    let t2 = a.sub(&x3);
    // T2 = T2 * B
    let t2 = t2.mul(&b);
    // Y3 = T2 - Y3
    let y3 = t2.sub(&y3);

    // lw[2] = Z3 * pre[2]
    let lw2 = z3.mul(pre2);
    // lw[1] = B * pre[3]
    let lw1 = b.mul(pre3);
    // B = B * pre[4]
    let b = b.mul(pre4);
    // lw[0] = 2*Y2*Z3
    let lw0 = y2.mul(&z3).double();
    // lw[0] = B - lw[0]
    let lw0 = b.sub(&lw0);

    // Update t in place
    *t = G2Point::new(x3, y3, z3);

    (lw0, lw1, lw2)
}

/// Line function for point addition without precomputed values
/// Based on GmSSL's sm9_z256_eval_g_line_no_pre
/// Computes pre values from T (the added point) on the fly
/// Updates P in place to P+T, returns lw[0], lw[1], lw[2]
fn line_function_add_lw_no_pre(p: &mut G2Point, t: &G2Point, q_aff: &(Fp, Fp)) -> (Fp2, Fp2, Fp2) {
    if p.is_identity() || t.is_identity() {
        return (Fp2::ZERO, Fp2::ZERO, Fp2::ZERO);
    }

    // Compute pre values from T (the added point)
    let pre0 = t.y.square();
    let pre4 = t.x.mul(&t.z).double();
    let t_z2 = t.z.square();
    let pre1 = t_z2.mul(&t.z);
    let pre2 = pre1.mul_fp(&q_aff.1).double();
    let pre3 = pre1.mul_fp(&q_aff.0).double().neg();

    let x1 = &p.x;
    let y1 = &p.y;
    let z1 = &p.z;
    let x2 = &t.x;
    let y2 = &t.y;
    let z2 = &t.z;

    // T1 = Z1^2
    let t1 = z1.square();
    // T2 = Z2^2
    let t2 = z2.square();
    // Z3 = (Z1 + Z2)^2 - T1 - T2
    let z3 = z1.add(z2).square().sub(&t1).sub(&t2);
    // A = X1 * T2
    let a = x1.mul(&t2);
    // B = X2 * T1
    let mut b = x2.mul(&t1);
    // C = 2 * Y1 * pre[1]
    let c = y1.mul(&pre1).double();
    // D = ((Y2 + Z1)^2 - pre[0] - T1) * T1
    let d = y2.add(z1).square().sub(&pre0).sub(&t1).mul(&t1);

    // B = B - A
    b = b.sub(&a);
    // Z3 = Z3 * B
    let z3 = z3.mul(&b);
    // T1 = (2*B)^2
    let t1 = b.double().square();
    // X3 = B * T1
    let x3 = b.mul(&t1);
    // Y3 = C * X3
    let y3 = c.mul(&x3);
    // A = A * T1
    let a = a.mul(&t1);
    // B = D - C
    let b = d.sub(&c);
    // T2 = 2*A
    let t2 = a.double();
    // X3 = X3 + T2
    let x3 = x3.add(&t2);
    // T2 = B^2
    let t2 = b.square();
    // X3 = T2 - X3
    let x3 = t2.sub(&x3);
    // T2 = A - X3
    let t2 = a.sub(&x3);
    // T2 = T2 * B
    let t2 = t2.mul(&b);
    // Y3 = T2 - Y3
    let y3 = t2.sub(&y3);

    // lw[2] = Z3 * pre[2]
    let lw2 = z3.mul(&pre2);
    // lw[1] = B * pre[3]
    let lw1 = b.mul(&pre3);
    // B = B * pre[4]
    let b = b.mul(&pre4);
    // lw[0] = 2*Y2*Z3
    let lw0 = y2.mul(&z3).double();
    // lw[0] = B - lw[0]
    let lw0 = b.sub(&lw0);

    // Update p in place
    *p = G2Point::new(x3, y3, z3);

    (lw0, lw1, lw2)
}

/// Final exponentiation: f^((p^12 - 1)/N)
///
/// Based on GmSSL's sm9_z256_final_exponent implementation.
///
/// The final exponent is decomposed as:
/// (p^12 - 1) / N = (p^6 - 1) * (p^2 + 1) * ((p^6 + 1) / N) / (p^2 + 1)
///
/// Step 1 (easy): f^(p^6 - 1)
/// Step 2 (easy): f1^(p^2 + 1)
/// Step 3 (hard): f2^((p^6 + 1) / N)
pub fn final_exponentiation(f: &Fp12) -> Fp12 {
    // Step 1: Easy part - f^(p^6 - 1)
    // f^(p^6) * f^(-1) = f^(p^6-1)
    let f_p6 = f.frobenius_six();
    let f_inv = f.inv().unwrap_or(Fp12::ONE);
    let f1 = f_p6.mul(&f_inv);

    // Step 2: f1^(p^2 + 1) = f1^(p^2) * f1
    let f1_p2 = f1.frobenius_sq();
    let f2 = f1_p2.mul(&f1);

    // Step 3: Hard part - f2^((p^6 + 1) / N)
    final_exponentiation_hard_part(&f2)
}

/// Hard part of final exponentiation
/// Based on GmSSL's sm9_z256_final_exponent_hard_part
///
/// Coefficients:
/// a2 = 0xd8000000019062ed0000b98b0cb27659
/// a3 = 0x2400000000215d941
fn final_exponentiation_hard_part(f: &Fp12) -> Fp12 {
    // a2 = 0xd8000000019062ed0000b98b0cb27659
    let a2 = Z256::new([0x0000b98b0cb27659, 0xd8000000019062ed, 0, 0]);
    // a3 = 0x2400000000215d941
    let a3 = Z256::new([0x400000000215d941, 0x2, 0, 0]);
    let nine = Z256::new([9, 0, 0, 0]);

    // t0 = f^(-a3)
    let mut t0 = f.pow(&a3);
    t0 = t0.inv().unwrap_or(Fp12::ONE);

    // t1 = t0^p
    let mut t1 = t0.frobenius();
    t1 = t0.mul(&t1);

    // t0 = t0 * t1
    t0 = t0.mul(&t1);

    // t2 = f^p
    let mut t2 = f.frobenius();
    // t3 = t2 * f = f^(p+1)
    let mut t3 = t2.mul(f);
    // t3 = t3^9 = f^(9*(p+1))
    t3 = t3.pow(&nine);

    // t0 = t0 * t3
    t0 = t0.mul(&t3);

    // t3 = f^2
    let mut t3 = f.square();
    // t3 = t3^2 = f^4
    t3 = t3.square();
    // t0 = t0 * t3 = t0 * f^4
    t0 = t0.mul(&t3);

    // t2 = t2^2 = f^(2p)
    t2 = t2.square();
    // t2 = t2 * t1 = f^(2p) * t0^(p+1)
    t2 = t2.mul(&t1);
    // t1 = f^(p^2)
    t1 = f.frobenius_sq();
    // t1 = t1 * t2
    t1 = t1.mul(&t2);

    // t2 = t1^a2
    let t2 = t1.pow(&a2);
    // t0 = t2 * t0
    t0 = t2.mul(&t0);
    // t1 = f^(p^3)
    t1 = f.frobenius_cu();
    // t1 = t1 * t0
    t1 = t1.mul(&t0);

    t1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::curve::g1::G1Point;
    use crate::pairing::curve::Identity;

    #[test]
    fn test_pairing_identity() {
        let p = G1Point::identity();
        let q = G2Point::identity();
        let result = pairing(&p, &q);
        assert!(result.is_one());
    }

    #[test]
    fn test_pairing_bilinearity() {
        // e(aP, bQ) = e(P, Q)^(ab)
        // This is the fundamental property
        // Full test requires working pairing implementation
    }
}
