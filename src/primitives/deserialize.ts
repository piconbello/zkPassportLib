import {
  assert,
  Bool,
  Bytes,
  DynamicProof,
  Field,
  type ProvablePure,
  PublicKey,
  Signature,
  Struct,
  UInt32,
  UInt64,
  UInt8,
} from "o1js";
import type {
  NestedProvable,
  NestedProvableFor,
  NestedProvablePure,
} from "./nested.ts";
import {
  type O1jsTypeName,
  type SerializedType,
  type SerializedValue,
  supportedTypes,
} from "./serialize.ts";
import { array, ProvableType } from "./o1js-missing.ts";
import { ProvableFactory } from "./provable-factory.ts";

export {
  deserializeNestedProvable,
  deserializeNestedProvableValue,
  deserializeProvable,
  deserializeProvablePureType,
  deserializeProvableType,
  replaceNull,
};

function deserializeProvableType(type: SerializedType): ProvableType<any> {
  if (ProvableFactory.isSerialized(type)) return ProvableFactory.fromJSON(type);

  if (type._type === "Constant") {
    return ProvableType.constant((type as any).value);
  }
  if (type._type === "Bytes") {
    return Bytes(type.size);
  }
  if (type._type === "Proof") {
    let proof = type.proof;
    let Proof = class extends DynamicProof<any, any> {
      static override publicInputType = deserializeProvablePureType(
        proof.publicInput,
      );
      static override publicOutputType = deserializeProvablePureType(
        proof.publicOutput,
      );
      static override maxProofsVerified = proof.maxProofsVerified;
      static override featureFlags = replaceNull(proof.featureFlags) as any;
    };
    Object.defineProperty(Proof, "name", { value: proof.name });
    return Proof;
  }
  if (type._type === "Struct") {
    let properties = deserializeNestedProvable(type.properties);
    return Struct(properties);
  }
  if (type._type === "Array") {
    let inner = deserializeProvableType(type.inner);
    return array(inner, type.size);
  }
  if (type._type === "String") {
    return String as any;
  }
  let result = supportedTypes[type._type];
  assert(result !== undefined, `Unsupported provable type: ${type._type}`);
  return result;
}

function deserializeProvable(json: SerializedValue): any {
  if (ProvableFactory.isSerialized(json)) {
    return ProvableFactory.valueFromJSON(json);
  }

  let { _type, value, properties } = json;
  switch (_type) {
    case "Field":
      return Field.fromJSON(value);
    case "Bool":
      return Bool(value === "true");
    case "UInt8":
      return UInt8.fromJSON({ value });
    case "UInt32":
      return UInt32.fromJSON(value);
    case "UInt64":
      return UInt64.fromJSON(value);
    case "PublicKey":
      return PublicKey.fromJSON(value);
    case "Signature":
      return Signature.fromJSON(value);
    case "Bytes":
      return Bytes.fromHex(value);
    case "Array":
      return (value as any[]).map((v: any) => deserializeProvable(v));
    case "Struct":
      let type = deserializeProvableType({ _type, properties }) as Struct<any>;
      return type.fromJSON(value);
    default:
      throw Error(`Unsupported provable type: ${_type}`);
  }
}

function deserializeProvablePureType(type: {
  _type: O1jsTypeName;
}): ProvablePure<any> {
  const provableType = deserializeProvableType(type);
  return provableType as ProvablePure<any>;
}

function deserializeNestedProvable(type: any): NestedProvable {
  if (typeof type === "object" && type !== null) {
    if ("_type" in type) {
      // basic provable type
      return deserializeProvableType(type);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (const [key, value] of Object.entries(type)) {
        result[key] = deserializeNestedProvable(value);
      }
      return result as NestedProvableFor<any>;
    }
  }
  throw Error(`Invalid type in NestedProvable: ${type}`);
}

function deserializeNestedProvablePure(type: any): NestedProvablePure {
  if (typeof type === "object" && type !== null) {
    if ("_type" in type) {
      // basic provable pure type
      return deserializeProvablePureType(type);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (const [key, value] of Object.entries(type)) {
        result[key] = deserializeNestedProvablePure(value);
      }
      return result as NestedProvablePure;
    }
  }
  throw Error(`Invalid type in NestedProvablePure: ${type}`);
}

function deserializeNestedProvableValue(value: any): any {
  if (typeof value === "string") return value;

  if (typeof value === "object" && value !== null) {
    if ("_type" in value) {
      // basic provable type
      return deserializeProvable(value);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (let [key, v] of Object.entries(value)) {
        result[key] = deserializeNestedProvableValue(v);
      }
      return result;
    }
  }

  throw Error(`Invalid nested provable value: ${value}`);
}

function replaceNull(obj: Record<string, any>): Record<string, any> {
  return Object.fromEntries(
    Object.entries(obj).map(([key, value]) => [
      key,
      value === null ? undefined : value,
    ]),
  );
}
