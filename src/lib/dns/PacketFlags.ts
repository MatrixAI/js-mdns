const AUTHORITATIVE_ANSWER_MASK = 0x400;
const TRUNCATION_MASK = 0x200;
const RECURSION_DESIRED_MASK = 0x100;
const RECURSION_AVAILABLE_MASK = 0x80;
const ZERO_HEADER_MASK = 0x40;
const AUTHENTIC_DATA_MASK = 0x20;
const CHECKING_DISABLED_MASK = 0x10;

export const decodePacketFlags = (flags: number): PacketFlags => {
  return {
    type: (flags >> 15),
    opcode: ((flags >> 11) & 0xf) as OpCode,
    rcode: (flags & 0xf) as RCode,

    authoritativeAnswer: Boolean(flags & AUTHORITATIVE_ANSWER_MASK),
    truncation: Boolean(flags & TRUNCATION_MASK),

    recursionDesired: Boolean(flags & RECURSION_DESIRED_MASK),
    recursionAvailable: Boolean(flags & RECURSION_AVAILABLE_MASK),
    zero: Boolean(flags & ZERO_HEADER_MASK),
    authenticData: Boolean(flags & AUTHENTIC_DATA_MASK),
    checkingDisabled: Boolean(flags & CHECKING_DISABLED_MASK),
  };
}

export const encodePacketFlags = (flags: PacketFlags): number => {
  let encodedFlags = 0;
  encodedFlags |= flags.type << 15;
  encodedFlags |= flags.opcode << 11;
  encodedFlags |= flags.rcode;

  if (flags.authoritativeAnswer) encodedFlags |= AUTHORITATIVE_ANSWER_MASK;
  if (flags.truncation) encodedFlags |= TRUNCATION_MASK;
  if (flags.recursionDesired) encodedFlags |= RECURSION_DESIRED_MASK;
  if (flags.recursionAvailable) encodedFlags |= RECURSION_AVAILABLE_MASK;
  if (flags.zero) encodedFlags |= ZERO_HEADER_MASK;
  if (flags.authenticData) encodedFlags |= AUTHENTIC_DATA_MASK;
  if (flags.checkingDisabled) encodedFlags |= CHECKING_DISABLED_MASK;

  return encodedFlags;
}

export type PacketFlags = {
  // Always Present
  type: PacketType;
  opcode: OpCode;
  rcode: RCode;

  authoritativeAnswer?: boolean;
  truncation?: boolean;

  // below flags are all not used with mdns
  recursionDesired?: boolean;
  recursionAvailable?: boolean;
  zero?: boolean;
  authenticData?: boolean;
  checkingDisabled?: boolean;
}

export enum PacketType {
  QUERY = 0,
  RESPONSE = 1, // 16th bit set
}

export enum OpCode { // RFC 6895 2.2.
  QUERY = 0,
  // incomplete list
}

export enum RCode { // RFC 6895 2.3.
  NoError = 0,
  // incomplete list
}
