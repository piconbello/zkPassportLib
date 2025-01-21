// TAKE SHA512 HASH OF A GIVEN DG1 (5+88 bytes => 744bits.) 
// Therefore, a single chunk (1024bit) implementation is sufficient.

/* 
References
https://en.wikipedia.org/wiki/SHA-2
https://github.com/digitalbazaar/forge/blob/main/lib/sha512.js
*/

/* 
SHA-512 is identical in structure to SHA-256, but:

the message is broken into 1024-bit chunks,
the initial hash values and round constants are extended to 64 bits,
there are 80 rounds instead of 64,
the message schedule array w has 80 64-bit words instead of 64 32-bit words,
to extend the message schedule array w, the loop is from 16 to 79 instead of from 16 to 63,
the round constants are based on the first 80 primes 2..409,
the word size used for calculations is 64 bits long,
the appended length of the message (before pre-processing), in bits, is a 128-bit big-endian integer, and
the shift and rotate amounts used are different.
*/


// Initial chunk details.
// L (original message length in bits) = 744 bits.
// length message = 128bits.
// 1 1. = 1 bit.
// K zeros = 1024 - 744 - 128 - 1 = 151 bits.
// Therefore, we have: <744bit message> 1 <151bit zeros> <128bit number L(744)>
// More specifically we have: <744bit message> 1 <269bit zeros> <1011101000>
// First 7 bytes (dg1 header + P<) are static.
// Last 280bits (35bytes) are static.

import { Field, UInt64, Provable, Struct, Unconstrained } from 'o1js';

const initialHashValues = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n, 
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
].map(h => UInt64.from(h));

const roundConstants = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn, 0x3956c25bf348b538n, 
  0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n, 0xd807aa98a3030242n, 0x12835b0145706fben, 
  0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n, 0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 
  0xc19bf174cf692694n, 0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n, 
  0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n, 0x983e5152ee66dfabn, 
  0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n, 0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 
  0x06ca6351e003826fn, 0x142929670a0e6e70n, 0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 
  0x53380d139d95b3dfn, 0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn, 
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n, 0xd192e819d6ef5218n, 
  0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n, 0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 
  0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n, 0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 
  0x682e6ff3d6b2b8a3n, 0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn, 
  0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn, 0xca273eceea26619cn, 
  0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n, 0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 
  0x113f9804bef90daen, 0x1b710b35131c471bn, 0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 
  0x431d67c49c100d4cn, 0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n
].map(k => UInt64.from(k));

const UInt64_16 = Provable.Array(UInt64, 16);
const UInt64_8 = Provable.Array(UInt64, 8);
const mask = 0xffffffffffffffffn;

const DG1_HEADER_CONSTANT =UInt64.from(0x615b5f1f58503c00n);
const MASK_FIRST_7BYTES = UInt64.from(0xffffffffffffff00n);
const FOOTER_CONSTANT = UInt64.from(0x0000000000800000n);
const MASK_LAST_24BIT = UInt64.from(0x0000000000ffffffn);
const ZERO = UInt64.from(0x0000000000000000n);
const LENGTH_PART = UInt64.from(744n);

export class SHA512MiniWrapper extends Struct({
  data: UInt64_16,
  hash: UInt64_8,
  value: Unconstrained.withEmpty(0n),
  hashValue: Unconstrained.withEmpty(0n),
}) {
  static from(x: bigint, hx: bigint): SHA512MiniWrapper {
    let data: UInt64[] = [];
    let value = x;
    for (let i = 0; i < 16; ++i) {
      data.push(UInt64.from(x & mask));
      x >>= 64n;
    }
    data.reverse(); // make it big endian.
    if (x!== 0n) {
      throw new Error("Value is not 1024-bit integer");
    }
    let hash: UInt64[] = [];
    let hashValue = hx;
    for (let i = 0; i < 8; ++i) {
      hash.push(UInt64.from(hx & mask));
      hx >>= 64n;
    }
    hash.reverse(); // make it big endian.
    if (hx !== 0n) {
      throw new Error("Hash value is not 512-bit integer");
    }

    return new SHA512MiniWrapper({ data, value: Unconstrained.from(value), hash, hashValue: Unconstrained.from(hashValue) });
  }

  static override check(x: { data: UInt64[], hash: UInt64[] }) {
    for (let i = 0; i < 16; ++i) {
      UInt64.check(x.data[i]);
    }
    for (let i = 0; i < 8; ++i) {
      UInt64.check(x.hash[i]);
    }
  }
}

export function formatCheck(x: SHA512MiniWrapper) {
  // format validation of input.
  (x.data[0].and(MASK_FIRST_7BYTES)).assertEquals(DG1_HEADER_CONSTANT);
  // WHAT'S IN BETWEEN IS DYNAMIC AND CORRESPONDS TO SHA512Mini CONTENT.
  (x.data[11].and(MASK_LAST_24BIT)).assertEquals(FOOTER_CONSTANT);
  for (let i = 12; i < 15; ++i) {
    x.data[i].assertEquals(ZERO);
  }
  x.data[15].assertEquals(LENGTH_PART);
  // TODO add checks for other stuff in SHA512Mini..
}

export function hashVerify(input: SHA512MiniWrapper) { // return big endian coded uint64 array of length 8.
  // hash the input.
  const w: UInt64[] = [];
  for (let i = 0; i < 16; ++i) {
    w.push(input.data[i]);
  }

  // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
  for (let i = 16; i < 80; ++i) {
    // SHA-512 Sum & Sigma:
    const s0 = ( w[i-15].rotate(1, 'right') ).xor( w[i-15].rotate(8, 'right') ).xor( w[i-15].rightShift(7) );
    const s1 = ( w[i-2].rotate(19, 'right') ).xor( w[i-2].rotate(61, 'right') ).xor( w[i-2].rightShift(6) );
    w[i] = w[i-16].addMod64(s0).addMod64(w[i-7]).addMod64(s1)
  };

  // Initialize working variables to current hash value:
 

  let a = UInt64.from(initialHashValues[0]);
  let b = UInt64.from(initialHashValues[1]);
  let c = UInt64.from(initialHashValues[2]);
  let d = UInt64.from(initialHashValues[3]);
  let e = UInt64.from(initialHashValues[4]);
  let f = UInt64.from(initialHashValues[5]);
  let g = UInt64.from(initialHashValues[6]);
  let h = UInt64.from(initialHashValues[7]);


  // Compression function main loop:
  for (let i = 0; i < 80; ++i) {
    // const ai = (80-i)%8;
    // const bi = (ai+1)%8;
    // const ci = (ai+2)%8;
    // const di = (ai+3)%8;
    // const ei = (ai+4)%8;
    // const fi = (ai+5)%8;
    // const gi = (ai+6)%8;
    // const hi = (ai+7)%8;

    const S1 = ( e.rotate(14, 'right') ).xor( e.rotate(18, 'right') ).xor( e.rotate(41, 'right') );
    const ch = ( e.and(f) ).xor( e.not().and(g) ); 
    const temp1 = h.addMod64(S1).addMod64(ch).addMod64(roundConstants[i]).addMod64(w[i]);
    const S0 = ( a.rotate(28, 'right') ).xor( a.rotate(34, 'right') ).xor( a.rotate(39, 'right') );
    const maj = ( a.and(b) ).xor( a.and(c) ).xor( b.and(c) );
    const temp2 = S0.addMod64(maj);

    h = g;
    g = f;
    f = e;
    e = d.addMod64(temp1);
    d = c;
    c = b;
    b = a;
    a = temp1.addMod64(temp2);
  }

  const v: UInt64[] = [];
  v.push(a);
  v.push(b);
  v.push(c);
  v.push(d);
  v.push(e);
  v.push(f);
  v.push(g);
  v.push(h);

  for (let i = 0; i < 8; ++i) {
    v[i] = v[i].addMod64(initialHashValues[i]);
  }

  // for (let i = 0; i < 16; ++i) {
  //   console.log(`#${i.toString().padStart(2, '0')}: ${
  //     input.data[i].toBigInt().toString(16).padStart(16, '0')
  //   }`);
  // }

  for (let i = 0; i < 8; ++i) {
    // console.log(`
    // #${i}: ${
    //   input.hash[i].toBigInt().toString(16).padStart(16,'0')
    // } = ${
    //   v[i].toBigInt().toString(16).padStart(16,'0')
    // }`)
    Provable.assertEqual(UInt64, input.hash[i], v[i]);
  }
}