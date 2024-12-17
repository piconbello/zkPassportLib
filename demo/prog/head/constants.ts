import { Bytes } from "o1js";
import { DynamicBytes } from "mina-credentials/dynamic";

// export const LDS_MAX_LENGTH = 648; // A LDS size for digest-size 32 amd 16 datagroups present.
export const LDS_MAX_LENGTH = 500;
export const DIGEST_SIZE = 32; // sha256
export const OFFSET_DG1_IN_LDS = 29; // fixed for sha256
export const OFFSET_LDS_IN_SIGNEDATTRS = 42; // fixed for sha256

export class LDS extends DynamicBytes({ maxLength: LDS_MAX_LENGTH }) {}
export class DG1_TD3 extends Bytes(93) {}
export class SIGNED_ATTRS extends Bytes(74) {}
