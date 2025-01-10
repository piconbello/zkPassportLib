// Modified rsa1 to 53 limbs/6144bits

/**
 * RSA signature verification with o1js
 */
import { Field, Gadgets, Provable, Struct, Unconstrained } from 'o1js';

export { Bigint6144, rsaVerify65537 };

const mask = (1n << 116n) - 1n;

/**
 * We use 116-bit limbs, which means 53 limbs for 6144-bit numbers as used in RSA.
 */
const Field53 = Provable.Array(Field, 53);

class Bigint6144 extends Struct({
  fields: Field53,
  value: Unconstrained.withEmpty(0n),
}) {
  modMul(x: Bigint6144, y: Bigint6144) {
    return multiply(x, y, this);
  }

  modSquare(x: Bigint6144) {
    return multiply(x, x, this, { isSquare: true });
  }

  toBigint() {
    return this.value.get();
  }

  static from(x: bigint) {
    let fields = [];
    let value = x;
    for (let i = 0; i < 53; i++) {
      fields.push(Field(x & mask));
      x >>= 116n;
    }
    return new Bigint6144({ fields, value: Unconstrained.from(value) });
  }

  static override check(x: { fields: Field[] }) {
    for (let i = 0; i < 53; i++) {
      rangeCheck116(x.fields[i]);
    }
  }
}

/**
 * x*y mod p
 */
function multiply(
  x: Bigint6144,
  y: Bigint6144,
  p: Bigint6144,
  { isSquare = false } = {}
) {
  if (isSquare) y = x;

  // witness q, r so that x*y = q*p + r
  // this also adds the range checks in `check()`
  let { q, r } = Provable.witness(
    // TODO Struct() should be unnecessary
    Struct({ q: Bigint6144, r: Bigint6144 }),
    () => {
      let xy = x.toBigint() * y.toBigint();
      let p0 = p.toBigint();
      let q = xy / p0;
      let r = xy - q * p0;
      return { q: Bigint6144.from(q), r: Bigint6144.from(r) };
    }
  );

  // compute delta = xy - qp - r
  // we can use a sum of native field products for each limb, because
  // input limbs are range-checked to 116 bits, and 2*116 + log(2*53-1) = 232 + 6 fits the native field.
  let delta: Field[] = Array.from({ length: 2 * 53 - 1 }, () => Field(0));
  let [X, Y, Q, R, P] = [x.fields, y.fields, q.fields, r.fields, p.fields];

  for (let i = 0; i < 53; i++) {
    // when squaring, we can save constraints by not computing xi * xj twice
    if (isSquare) {
      for (let j = 0; j < i; j++) {
        delta[i + j] = delta[i + j].add(X[i].mul(X[j]).mul(2n));
      }
      delta[2 * i] = delta[2 * i].add(X[i].mul(X[i]));
    } else {
      for (let j = 0; j < 53; j++) {
        delta[i + j] = delta[i + j].add(X[i].mul(Y[j]));
      }
    }

    for (let j = 0; j < 53; j++) {
      delta[i + j] = delta[i + j].sub(Q[i].mul(P[j]));
    }

    delta[i] = delta[i].sub(R[i]).seal();
  }

  // perform carrying on the difference to show that it is zero
  let carry = Field(0);

  for (let i = 0; i < 2 * 53 - 2; i++) {
    let deltaPlusCarry = delta[i].add(carry).seal();

    carry = Provable.witness(Field, () => deltaPlusCarry.div(1n << 116n));
    rangeCheck128Signed(carry);

    // (xy - qp - r)_i + c_(i-1) === c_i * 2^116
    // proves that bits i*116 to (i+1)*116 of res are zero
    deltaPlusCarry.assertEquals(carry.mul(1n << 116n));
  }

  // last carry is 0 ==> all of diff is 0 ==> x*y = q*p + r as integers
  delta[2 * 53 - 2].add(carry).assertEquals(0n);

  return r;
}

/**
 * RSA signature verification
 *
 * TODO this is a bit simplistic; according to RSA spec, message must be 256 bits
 * and the remaining bits must follow a specific pattern.
 */
function rsaVerify65537(
  message: Bigint6144,
  signature: Bigint6144,
  modulus: Bigint6144
) {
  // compute signature^(2^16 + 1) mod modulus
  // square 16 times
  let x = signature;
  for (let i = 0; i < 16; i++) {
    x = modulus.modSquare(x);
  }
  // multiply by signature
  x = modulus.modMul(x, signature);

  // check that x == message
  Provable.assertEqual(Bigint6144, message, x);
}

/**
 * Custom range check for a single limb, x in [0, 2^116)
 */
function rangeCheck116(x: Field) {
  let [x0, x1] = Provable.witnessFields(2, () => [
    x.toBigInt() & ((1n << 64n) - 1n),
    x.toBigInt() >> 64n,
  ]);

  Gadgets.rangeCheck64(x0);
  let [x52] = Gadgets.rangeCheck64(x1);
  x52.assertEquals(0n); // => x1 is 52 bits
  // 64 + 52 = 116
  x0.add(x1.mul(1n << 64n)).assertEquals(x);
}

/**
 * Custom range check for carries, x in [-2^127, 2^127)
 */
function rangeCheck128Signed(xSigned: Field) {
  let x = xSigned.add(1n << 127n);

  let [x0, x1] = Provable.witnessFields(2, () => {
    const x0 = x.toBigInt() & ((1n << 64n) - 1n);
    const x1 = x.toBigInt() >> 64n;
    return [x0, x1];
  });

  Gadgets.rangeCheck64(x0);
  Gadgets.rangeCheck64(x1);

  x0.add(x1.mul(1n << 64n)).assertEquals(x);
}