// Modified rsa1 to 36 limbs/4096bits

/**
 * RSA signature verification with o1js
 */
import { Field, Gadgets, Provable, Struct, Unconstrained, UInt32 } from 'o1js';

export { Bigint4096, rsaVerify, EXP_BIT_COUNT };

const mask = (1n << 116n) - 1n;

const EXP_BIT_COUNT = 20;

/**
 * We use 116-bit limbs, which means 36 limbs for 4096-bit numbers as used in RSA.
 */
export const Field36 = Provable.Array(Field, 36);

class Bigint4096 extends Struct({
  fields: Field36,
  value: Unconstrained.withEmpty(0n),
}) {
  modMul(x: Bigint4096, y: Bigint4096) {
    return multiply(x, y, this);
  }

  modSquare(x: Bigint4096) {
    return multiply(x, x, this, { isSquare: true });
  }

  toBigint() {
    return this.value.get();
  }

  toFields() {
    return this.fields;
  }

  static from(x: bigint) {
    let fields = [];
    let value = x;
    for (let i = 0; i < 36; i++) {
      fields.push(Field(x & mask));
      x >>= 116n;
    }
    return new Bigint4096({ fields, value: Unconstrained.from(value) });
  }

  static override check(x: { fields: Field[] }) {
    for (let i = 0; i < 36; i++) {
      rangeCheck116(x.fields[i]);
    }
  }
}

/**
 * x*y mod p
 */
function multiply(
  x: Bigint4096,
  y: Bigint4096,
  p: Bigint4096,
  { isSquare = false } = {}
) {
  if (isSquare) y = x;

  // witness q, r so that x*y = q*p + r
  // this also adds the range checks in `check()`
  let { q, r } = Provable.witness(
    // TODO Struct() should be unnecessary
    Struct({ q: Bigint4096, r: Bigint4096 }),
    () => {
      let xy = x.toBigint() * y.toBigint();
      let p0 = p.toBigint();
      let q = xy / p0;
      let r = xy - q * p0;
      return { q: Bigint4096.from(q), r: Bigint4096.from(r) };
    }
  );

  // compute delta = xy - qp - r
  // we can use a sum of native field products for each limb, because
  // input limbs are range-checked to 116 bits, and 2*116 + log(2*36-1) = 232 + 6 fits the native field.
  let delta: Field[] = Array.from({ length: 2 * 36 - 1 }, () => Field(0));
  let [X, Y, Q, R, P] = [x.fields, y.fields, q.fields, r.fields, p.fields];

  for (let i = 0; i < 36; i++) {
    // when squaring, we can save constraints by not computing xi * xj twice
    if (isSquare) {
      for (let j = 0; j < i; j++) {
        delta[i + j] = delta[i + j].add(X[i].mul(X[j]).mul(2n));
      }
      delta[2 * i] = delta[2 * i].add(X[i].mul(X[i]));
    } else {
      for (let j = 0; j < 36; j++) {
        delta[i + j] = delta[i + j].add(X[i].mul(Y[j]));
      }
    }

    for (let j = 0; j < 36; j++) {
      delta[i + j] = delta[i + j].sub(Q[i].mul(P[j]));
    }

    delta[i] = delta[i].sub(R[i]).seal();
  }

  // perform carrying on the difference to show that it is zero
  let carry = Field(0);

  for (let i = 0; i < 2 * 36 - 2; i++) {
    let deltaPlusCarry = delta[i].add(carry).seal();

    carry = Provable.witness(Field, () => deltaPlusCarry.div(1n << 116n));
    rangeCheck128Signed(carry);

    // (xy - qp - r)_i + c_(i-1) === c_i * 2^116
    // proves that bits i*116 to (i+1)*116 of res are zero
    deltaPlusCarry.assertEquals(carry.mul(1n << 116n));
  }

  // last carry is 0 ==> all of diff is 0 ==> x*y = q*p + r as integers
  delta[2 * 36 - 2].add(carry).assertEquals(0n);

  return r;
}

// Using Field
// using toBits(24) => totalRows: 125847
// using toBits(20) => totalRows: 104011


// Using Field
// totalRows: 170244

const zero = Field.from(0n);

function rsaVerify(
  message: Bigint4096,
  signature: Bigint4096,
  modulus: Bigint4096,
  publicExponent: Field
) {
  const one = Bigint4096.from(1n);
  const bits = publicExponent.toBits(EXP_BIT_COUNT);
  let x = Provable.if(bits[EXP_BIT_COUNT-1], signature, one);
  for (let i = EXP_BIT_COUNT-2; i >= 0; i--) {
    x = modulus.modSquare(x);
    x = modulus.modMul(x, Provable.if(bits[i], signature, one));
  }
  Provable.assertEqual(Bigint4096, message, x);
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