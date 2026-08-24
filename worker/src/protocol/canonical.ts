export const MAX_PROTOCOL_BYTES = 65_536;

export class ProtocolCodecError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProtocolCodecError";
  }
}

export function canonicalize(value: unknown): string {
  const encoded = JSON.stringify(sortValue(value));
  if (encoded === undefined) {
    throw new ProtocolCodecError("protocol value is not JSON");
  }
  if (encoded.length > MAX_PROTOCOL_BYTES) {
    throw new ProtocolCodecError("protocol body exceeds bound");
  }
  return encoded;
}

export function parseCanonical(text: string): unknown {
  if (text.length === 0 || text.length > MAX_PROTOCOL_BYTES) {
    throw new ProtocolCodecError("protocol body exceeds bound");
  }
  const parsed: unknown = JSON.parse(text);
  if (canonicalize(parsed) !== text) {
    throw new ProtocolCodecError("protocol body is not canonical");
  }
  return parsed;
}

function sortValue(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new ProtocolCodecError("protocol number is not canonical");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (typeof value === "object") {
    const input = value as Record<string, unknown>;
    const output: Record<string, unknown> = {};
    for (const key of Object.keys(input).sort()) {
      const next = input[key];
      if (next === undefined) {
        throw new ProtocolCodecError(
          "protocol object omitted a required field",
        );
      }
      output[key] = sortValue(next);
    }
    return output;
  }
  throw new ProtocolCodecError("protocol value has a non-JSON type");
}
