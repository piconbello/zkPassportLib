## Evolution

* *rsa65537/rsa0*: [rsa.ts](https://github.com/o1-labs/o1js/blob/main/src/examples/crypto/rsa/rsa.ts
* *rsa65537/rsa1*: Instead of using 18 limbs of 116bits, use 17 limbs of 121bits. (range check was better)
* *rsa65537/rsa2*: Use 36 limbs of 116bits for 4096bit
* *rsa/rsa3*: 4096bit with exponent as input. 104k constraints won't fit.
* *rsa/run4*: 4096bit with exponent as input but as a recursive zkprogram.
* *rsa65537/rsa5*: Use 53 limbs of 116bits for 6144bit
* *rsa/run6*: 6144bit with exponent as input but as a recursive 