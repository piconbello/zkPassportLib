export { sha512Bigint, DG1BytesFromBase64, sampleDG1BigInt, sampleDG1HashBigInt, makeChunkFromDG1Bytes }

function bytesToBigintBE(bytes: Uint8Array | number[]) {
  let x = 0n;
  for (let i = 0; i < bytes.length; ++i) {
    x <<= 8n;
    x += BigInt(bytes[i]);
  }
  return x;
}

async function sha512Bigint(dg1Bytes: Uint8Array) {
  let digestBytes = new Uint8Array(
    await crypto.subtle.digest('SHA-512', dg1Bytes)
  );
  return bytesToBigintBE(digestBytes);
}

function makeChunkFromDG1Bytes(dg1Bytes: Uint8Array) {
  if (dg1Bytes.length !== 93) {
    throw new Error('DG1 should be 93 bytes long');
  }
  const res = new Uint8Array(128);
  res.set(dg1Bytes, 0);
  res[93] = 1<<7;
  // 93 * 8 = 744. which is 0x02e8
  res[126] = 0x02;
  res[127] = 0xe8;
  return bytesToBigintBE(res);
}

function DG1BytesFromBase64(base64: string) {
  const binaryString = atob(base64);
  if (binaryString.length !== 93) {
    console.log('binary string length is', binaryString.length, 'expected 93' );
    throw new Error('Invalid base64 input for DG1');
  }
  const bytes = new Uint8Array(93);
  for (let i = 0; i < 93; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

const sampleDG1Base64 = "YVtfH1hQPEdCUkJBR0dJTlM8PEZST0RPPDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PFAyMzE0NTg5MDFHQlI2NzA5MjI0TTIyMDkxNTFaRTE4NDIyNkI8PDw8PDE4";
const sampleDG1BigInt = makeChunkFromDG1Bytes(DG1BytesFromBase64(sampleDG1Base64));
const sampleDG1HashBigInt = 0xabf209f54b9d59a77e5ca72ff450cd3d73189255bbb2f4671e7cc10d82deb10ffc922f9dc213d63eaa4ec266b2e2745e22692a8e3282ebb4a078cb9bf1e4b3e3n;

await (async () => {
  const hash1 = await sha512Bigint(DG1BytesFromBase64(sampleDG1Base64));
  if (hash1!== sampleDG1HashBigInt) {
    throw new Error('SHA-512 hash mismatch');
  }
})()