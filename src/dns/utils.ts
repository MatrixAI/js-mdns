import type {
  Parsed,
  Packet,
  PacketFlags,
  QuestionRecord,
  ResourceRecord,
  StringRecord,
  SRVRecordValue,
  TXTRecordValue,
  PacketHeader,
  CachableResourceRecord,
} from './types';
import type { Hostname, Port } from '../types';
import { IPv6 } from 'ip-num';
import * as errors from './errors';

// Packet Flag Masks
const AUTHORITATIVE_ANSWER_MASK = 0x400;
const TRUNCATION_MASK = 0x200;
const RECURSION_DESIRED_MASK = 0x100;
const RECURSION_AVAILABLE_MASK = 0x80;
const ZERO_HEADER_MASK = 0x40;
const AUTHENTIC_DATA_MASK = 0x20;
const CHECKING_DISABLED_MASK = 0x10;

// QR Masks
const QU_MASK = 0x8000; // 2 bytes, first bit set (Unicast)
const NOT_QU_MASK = 0x7fff;

// RR masks
const FLUSH_MASK = 0x8000; // 2 bytes, first bit set (Flush)
const NOT_FLUSH_MASK = 0x7fff;

const enum PacketType {
  QUERY = 0,
  RESPONSE = 1, // 16th bit set
}

const enum PacketOpCode { // RFC 6895 2.2.
  QUERY = 0,
  // Incomplete list
}

const enum RCode { // RFC 6895 2.3.
  NoError = 0,
  // Incomplete list
}

// Question RR Types
const enum QType { // RFC 1035 3.2.2. 3.2.3.
  A = 1,
  CNAME = 5,
  PTR = 12,
  TXT = 16,
  AAAA = 28, // RFC 3596 2.1.
  SRV = 33, // RFC 2782
  OPT = 41, // RFC 6891
  NSEC = 47, // RFC 4034 4.
  ANY = 255,
}

// Question RR Classes
const enum QClass { // RFC 1035 3.2.4. 3.2.5.
  IN = 1, // The internet
  ANY = 255,
}

// Answer RR Types
const enum RType { // RFC 1035 3.2.2.
  A = 1,
  CNAME = 5,
  PTR = 12,
  TXT = 16,
  AAAA = 28, // RFC 3596 2.1.
  SRV = 33, // RFC 2782
  OPT = 41, // RFC 6891
  NSEC = 47, // RFC 4034 4.
  // incomplete list
}

// Answer RR Classes
const enum RClass { // RFC 1035 3.2.4.
  IN = 1, // The internet
  // incomplete list
}

function concatUInt8Array(...arrays: Array<Uint8Array>) {
  const totalLength = arrays.reduce((acc, val) => acc + val.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function encodeUInt16BE(value: number): Uint8Array {
  const buffer = new Uint8Array(2);
  new DataView(buffer.buffer).setUint16(0, value, false);
  return buffer;
}

function encodeUInt32BE(value: number): Uint8Array {
  const buffer = new Uint8Array(4);
  new DataView(buffer.buffer).setUint32(0, value, false);
  return buffer;
}

// RFC 1035 4.1.4. Message compression:
//  In order to reduce the size of messages, the domain system utilizes a
//   compression scheme which eliminates the repetition of domain names in a
//   message.  In this scheme, an entire domain name or a list of labels at
//   the end of a domain name is replaced with a pointer to a PRIOR occurrence
//   of the same name.
//
//  The compression scheme allows a domain name in a message to be
//  represented as either:
//    - a sequence of labels ending in a zero octet
//    - a pointer
//    - a sequence of labels ending with a pointer
// Revisit this later in case incorrect
function parseLabels(
  input: Uint8Array,
  original: Uint8Array,
  compression: boolean = true,
): Parsed<Hostname> {
  let currentIndex = 0;
  let label = '';
  let readBytes = 0;

  let foundInitialPointer = false;
  let currentBuffer = input;

  const traversedPointers: Array<number> = [];

  while (
    currentBuffer[currentIndex] !== 0 &&
    currentIndex < currentBuffer.length
  ) {
    if ((currentBuffer[currentIndex] & 0xc0) === 0xc0 && compression) {
      const dv = new DataView(currentBuffer.buffer, currentBuffer.byteOffset);
      const pointerOffset = dv.getUint16(currentIndex, false) & 0x3fff;

      if (traversedPointers.includes(pointerOffset)) {
        throw new errors.ErrorDNSParse(
          'Name compression pointer causes recursion',
        );
      }
      traversedPointers.push(pointerOffset);

      currentIndex = pointerOffset; // Set the currentIndex to the offset of the pointer in relation to the original buffer that is passed in

      if (!foundInitialPointer) {
        foundInitialPointer = true; // The initial, or outermost pointer has been found
        currentBuffer = original; // Set the currentBuffer to the original buffer to get the full scope of the packet
      }
    } else {
      const labelLength = currentBuffer[currentIndex++];
      label += new TextDecoder().decode(
        currentBuffer.subarray(currentIndex, currentIndex + labelLength),
      );
      label += '.';
      currentIndex += labelLength;
      if (!foundInitialPointer) readBytes += 1 + labelLength; // Label Length Byte + Length of Label Itself
    }
  }

  if (!foundInitialPointer) {
    readBytes += 1;
  } // Include the terminating null byte if the pointer has not been found
  else {
    readBytes += 2;
  }

  return {
    data: label.slice(0, -1) as Hostname,
    remainder: input.subarray(readBytes),
  };
}

// Revisit this later...
function generateLabels(
  input: Hostname,
  terminator: Array<number> = [0],
): Uint8Array {
  const labels = input.split('.');
  const encodedName: Array<number> = [];

  for (const label of labels) {
    encodedName.push(label.length);

    for (let i = 0; i < label.length; i++) {
      const codePoint = label.codePointAt(i);
      if (codePoint === undefined) {
        continue;
      }

      if (codePoint > 127) {
        // Code point requires UTF-8 encoding
        const encodedBytes = Array.from(
          new TextEncoder().encode(label.charAt(i)),
        );
        encodedName.push(...encodedBytes);
      } else {
        // ASCII character, no encoding needed
        encodedName.push(codePoint);
      }
    }
  }

  encodedName.push(...terminator); // Terminating null byte

  return new Uint8Array(encodedName);
}

function parseIPv6(input: Uint8Array): Parsed<string> {
  if (input.length < 16) throw new errors.ErrorDNSParse('Invalid IPv6 address');

  const dv = new DataView(input.buffer, input.byteOffset);
  const parts: Array<string> = [];

  for (let i = 0; i < 16; i += 2) {
    const value = dv.getUint16(i, false).toString(16);
    parts.push(value);
  }

  return {
    data: parts.join(':'),
    remainder: input.subarray(16),
  };
}

function generateIPv6(ip: string): Uint8Array {
  const buffer = new Uint8Array(16);
  const dv = new DataView(buffer.buffer);
  try {
    const ipv6 = new IPv6(ip);
    const parts = ipv6.getHexadecatet();
    for (let i = 0; i < 8; i++) {
      dv.setUint16(i * 2, parts[i].getValue(), false);
    }
  } catch (err) {
    throw new errors.ErrorDNSGenerate('Invalid IPv6 address');
  }

  return buffer;
}

function parsePacket(input: Uint8Array): Packet {
  let inputBuffer = input;

  const { data: header, remainder: postHeaderRemainder } =
    parsePacketHeader(input);
  inputBuffer = postHeaderRemainder;

  const { data: questions, remainder: postQuestionRemainder } =
    parseQuestionRecords(inputBuffer, input, header.qdcount);
  inputBuffer = postQuestionRemainder;

  const { data: answers, remainder: postAnswerRemainder } =
    parseResourceRecords(inputBuffer, input, header.ancount);
  inputBuffer = postAnswerRemainder;

  const { data: authorities, remainder: postAuthorityRemainder } =
    parseResourceRecords(inputBuffer, input, header.nscount);
  inputBuffer = postAuthorityRemainder;

  const { data: additionals, remainder: postAdditionalRemainder } =
    parseResourceRecords(inputBuffer, input, header.arcount);
  inputBuffer = postAdditionalRemainder;

  return {
    id: header.id,
    flags: header.flags,
    questions,
    answers,
    authorities,
    additionals,
  };
}

function parsePacketHeader(input: Uint8Array): Parsed<PacketHeader> {
  if (input.length < 12) {
    throw new errors.ErrorDNSParse('Packet header is too short');
  }

  const dv = new DataView(input.buffer, input.byteOffset);

  const id = dv.getUint16(0, false);
  const flags = parsePacketFlags(input.subarray(2, 4)).data;

  const qdcount = dv.getUint16(4, false); // Question Count
  const ancount = dv.getUint16(6, false); // Answer Count
  const nscount = dv.getUint16(8, false); // Authority Count
  const arcount = dv.getUint16(10, false); // Additional Count

  return {
    data: {
      id,
      flags,
      qdcount,
      ancount,
      nscount,
      arcount,
    },
    remainder: input.subarray(12),
  };
}

function parsePacketFlags(input: Uint8Array): Parsed<PacketFlags> {
  if (input.length < 2) {
    throw new errors.ErrorDNSParse('Packet flags are too short');
  }

  const dv = new DataView(input.buffer, input.byteOffset);
  const flags = dv.getUint16(0, false);
  return {
    data: {
      type: flags >> 15,
      opcode: ((flags >> 11) & 0xf) as PacketOpCode,
      rcode: (flags & 0xf) as RCode,

      authoritativeAnswer: Boolean(flags & AUTHORITATIVE_ANSWER_MASK),
      truncation: Boolean(flags & TRUNCATION_MASK),

      recursionDesired: Boolean(flags & RECURSION_DESIRED_MASK),
      recursionAvailable: Boolean(flags & RECURSION_AVAILABLE_MASK),
      zero: Boolean(flags & ZERO_HEADER_MASK),
      authenticData: Boolean(flags & AUTHENTIC_DATA_MASK),
      checkingDisabled: Boolean(flags & CHECKING_DISABLED_MASK),
    },
    remainder: input.subarray(2),
  };
}

function generatePacket(packet: Packet): Uint8Array {
  const packetHeaderBuffer = generatePacketHeader({
    id: packet.id,
    flags: packet.flags,
    qdcount: packet.questions.length,
    ancount: packet.answers.length,
    nscount: packet.authorities.length,
    arcount: packet.additionals.length,
  });
  return concatUInt8Array(
    packetHeaderBuffer,
    generateQuestionRecords(packet.questions),
    generateResourceRecords(packet.answers),
    generateResourceRecords(packet.authorities),
    generateResourceRecords(packet.additionals),
  );
}

function generatePacketHeader(header: PacketHeader): Uint8Array {
  const packetHeaderBuffer = new Uint8Array(12);
  const dv = new DataView(packetHeaderBuffer.buffer);
  dv.setUint16(0, header.id, false);
  packetHeaderBuffer.set(generatePacketFlags(header.flags), 2);
  dv.setUint16(4, header.qdcount, false);
  dv.setUint16(6, header.ancount, false);
  dv.setUint16(8, header.nscount, false);
  dv.setUint16(10, header.arcount, false);

  return packetHeaderBuffer;
}

function generatePacketFlags(flags: PacketFlags): Uint8Array {
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

  return encodeUInt16BE(encodedFlags);
}

function parseQuestionRecords(
  input: Uint8Array,
  original: Uint8Array,
  qdcount: number = 1,
): Parsed<Array<QuestionRecord>> {
  let inputBuffer = input;

  const questions: Array<QuestionRecord> = [];

  while (inputBuffer.length !== 0 && questions.length < qdcount) {
    const { data, remainder } = parseQuestionRecord(inputBuffer, original);
    questions.push(data);
    inputBuffer = remainder;
  }

  return {
    data: questions,
    remainder: inputBuffer,
  };
}

function parseQuestionRecord(
  input: Uint8Array,
  original: Uint8Array,
): Parsed<QuestionRecord> {
  let inputBuffer = input;

  const { data: name, remainder } = parseLabels(inputBuffer, original);
  inputBuffer = remainder;

  if (inputBuffer.length < 4) {
    throw new errors.ErrorDNSParse('Question record is too short');
  }

  const dv = new DataView(remainder.buffer, remainder.byteOffset);
  const type = dv.getUint16(0, false);
  const qclass = dv.getUint16(2, false);

  const questionRecord: QuestionRecord = {
    name,
    type,
    class: qclass & NOT_QU_MASK,
    unicast: Boolean(qclass & QU_MASK),
  };

  inputBuffer = inputBuffer.subarray(4);

  return {
    data: questionRecord,
    remainder: inputBuffer,
  };
}

function generateQuestionRecords(questions: Array<QuestionRecord>): Uint8Array {
  return concatUInt8Array(...questions.flatMap(generateQuestionRecord));
}

function generateQuestionRecord(question: QuestionRecord): Uint8Array {
  const encodedName = generateLabels(question.name);

  const encodedQuestionBuffer = new Uint8Array(encodedName.length + 4);
  encodedQuestionBuffer.set(encodedName, 0);

  const dv = new DataView(encodedQuestionBuffer.buffer, encodedName.length);

  dv.setUint16(0, question.type, false);
  dv.setUint16(
    2,
    question.class | (question.unicast ? QU_MASK : 0x0000),
    false,
  );
  // Implement name compression later
  return encodedQuestionBuffer;
}

function parseResourceRecords(
  input: Uint8Array,
  original: Uint8Array,
  rrcount: number = 1,
): Parsed<Array<ResourceRecord>> {
  let inputBuffer = input;

  const records: Array<ResourceRecord> = [];

  while (inputBuffer.length !== 0 && records.length < rrcount) {
    const { data: resourceRecord, remainder } = parseResourceRecord(
      inputBuffer,
      original,
    );
    records.push(resourceRecord);
    inputBuffer = remainder;
  }

  return {
    data: records,
    remainder: inputBuffer,
  };
}

function parseResourceRecord(
  input: Uint8Array,
  original: Uint8Array,
): Parsed<ResourceRecord> {
  let inputBuffer = input;
  const { data: name, remainder } = parseLabels(inputBuffer, original);
  inputBuffer = remainder;

  const dv = new DataView(inputBuffer.buffer, inputBuffer.byteOffset);

  let flush = false;

  if (inputBuffer.length < 10) {
    throw new errors.ErrorDNSParse('Resource record is too short');
  }
  const type: RType = dv.getUint16(0, false);
  let rclass: RClass = dv.getUint16(2, false);

  // Flush bit cannot exist on OPT records
  if (type !== RType.OPT) {
    flush = Boolean(rclass & FLUSH_MASK);
    rclass = rclass & NOT_FLUSH_MASK;
  }

  const ttl = dv.getUint32(4, false);
  const rdlength = dv.getUint16(8, false);

  inputBuffer = inputBuffer.subarray(10);

  let parser: () => Parsed<any>;

  if (isStringRType(type)) {
    if (type === RType.A) {
      parser = () => parseARecordData(inputBuffer, rdlength);
    } else if (type === RType.AAAA) {
      parser = () => parseAAAARecordData(inputBuffer, rdlength);
    } else {
      parser = () => parseLabels(inputBuffer, original);
    }
  } else if (type === RType.TXT) {
    parser = () => parseTXTRecordData(inputBuffer, rdlength);
  } else if (type === RType.SRV) {
    parser = () => parseSRVRecordData(inputBuffer, original, rdlength);
  } else {
    parser = () => ({ data: '', remainder: inputBuffer.subarray(rdlength) });
    // Todo, OPT, NSEC etc
  }

  const parsedValue = parser();
  return {
    data: {
      name,
      type,
      class: rclass,
      flush,
      ttl,
      data: parsedValue.data,
    } as ResourceRecord,
    remainder: parsedValue.remainder,
  };
}

function parseARecordData(input: Uint8Array, rdlength = 4): Parsed<string> {
  return {
    data: input.subarray(0, 4).join('.'),
    remainder: input.subarray(rdlength),
  };
}

function parseAAAARecordData(
  input: Uint8Array,
  _rdlength = input.length,
): Parsed<string> {
  return parseIPv6(input);
}

function parseTXTRecordData(
  input: Uint8Array,
  rdlength: number = input.length,
): Parsed<TXTRecordValue> {
  let inputBuffer = input.subarray(0, rdlength);
  const txtAttributes: TXTRecordValue = {};

  while (inputBuffer.length !== 0) {
    const textLength = inputBuffer[0];
    const decodedPair = new TextDecoder('utf-8', { fatal: false }).decode(
      inputBuffer.subarray(1, textLength + 1),
    );

    const [key, value] = decodedPair.split('=', 2);
    if (key !== '__proto__') {
      txtAttributes[key] = typeof value !== 'undefined' ? value : '';
    }
    inputBuffer = inputBuffer.subarray(textLength + 1);
  }

  return {
    data: txtAttributes,
    remainder: input.subarray(rdlength),
  };
}

function parseSRVRecordData(
  input: Uint8Array,
  original: Uint8Array,
  rdlength: number = input.length,
): Parsed<SRVRecordValue> {
  if (input.length < 6 || rdlength < 6) {
    throw new errors.ErrorDNSParse('SRV record data is too short');
  }

  const dv = new DataView(input.buffer, input.byteOffset);
  const priority = dv.getUint16(0, false);
  const weight = dv.getUint16(2, false);
  const port = dv.getUint16(4, false) as Port;

  const target = parseLabels(input.subarray(6), original);

  return {
    data: {
      port,
      priority,
      weight,
      target: target.data,
    },
    remainder: input.subarray(rdlength),
  };
}

function generateResourceRecords(records: Array<ResourceRecord>): Uint8Array {
  return concatUInt8Array(...records.flatMap(generateResourceRecord));
}

function generateResourceRecord(record: ResourceRecord): Uint8Array {
  // Implement Name Compression Later
  const encodedName = generateLabels(record.name);

  let rdata: Uint8Array;
  if (record.type === RType.A) {
    rdata = generateARecordData(record.data);
  } else if (record.type === RType.AAAA) {
    rdata = generateAAAARecordData(record.data);
  } else if (record.type === RType.CNAME || record.type === RType.PTR) {
    rdata = generateLabels(record.data);
  } else if (record.type === RType.TXT) {
    rdata = generateTXTRecordData(record.data);
  } else if (record.type === RType.SRV) {
    rdata = generateSRVRecordData(record.data);
  } else if (record.type === RType.OPT) {
    return new Uint8Array();
  } else {
    rdata = new Uint8Array();
  }

  // Encoded Name + Type (2 Bytes) + Class (2 Bytes) + TTL (4 Bytes) + RDLength (2 Bytes) + RData
  const resourceRecordBuffer = new Uint8Array(
    encodedName.length + 10 + rdata.length,
  );
  const dv = new DataView(resourceRecordBuffer.buffer, encodedName.length);
  resourceRecordBuffer.set(encodedName, 0);
  dv.setUint16(0, record.type, false);
  dv.setUint16(2, record.class | (record.flush ? FLUSH_MASK : 0x0000), false);
  dv.setUint32(4, record.ttl, false);
  dv.setUint16(8, rdata.length, false);
  resourceRecordBuffer.set(rdata, encodedName.length + 10);

  return resourceRecordBuffer;
}

function generateARecordData(data: string): Uint8Array {
  return new Uint8Array(data.split('.').map((v) => Number(v)));
}

function generateAAAARecordData(data: string): Uint8Array {
  return generateIPv6(data);
}

function generateTXTRecordData(data: TXTRecordValue): Uint8Array {
  const encodedAttributes = Object.entries(data).flatMap(([key, val]) => {
    const encodedPair = new TextEncoder().encode(`${key}=${val}`);
    return [encodedPair.length, ...encodedPair];
  });
  return new Uint8Array(encodedAttributes);
}

function generateSRVRecordData(data: SRVRecordValue): Uint8Array {
  const buffer = new Uint8Array(6);
  const dv = new DataView(buffer.buffer);

  dv.setUint16(0, data.priority, false);
  dv.setUint16(2, data.weight, false);
  dv.setUint16(4, data.port, false);

  return concatUInt8Array(buffer, generateLabels(data.target));
}

function isStringResourceRecord(
  record: ResourceRecord,
): record is StringRecord {
  return isStringRType(record.type);
}

function isStringRType(type: RType): type is StringRecord['type'] {
  return [RType.A, RType.AAAA, RType.CNAME, RType.PTR].includes(type);
}

function isCachableResourceRecord(
  record: ResourceRecord,
): record is CachableResourceRecord {
  return isCachableRType(record.type);
}

function isCachableRType(type: RType): type is CachableResourceRecord['type'] {
  return [
    RType.A,
    RType.AAAA,
    RType.CNAME,
    RType.PTR,
    RType.NSEC,
    RType.TXT,
    RType.SRV,
  ].includes(type);
}

export {
  PacketOpCode,
  PacketType,
  RType,
  RCode,
  RClass,
  QType,
  QClass,
  concatUInt8Array,
  encodeUInt16BE,
  encodeUInt32BE,
  parseLabels,
  generateLabels,
  parseIPv6,
  generateIPv6,
  parsePacket,
  parsePacketFlags,
  generatePacket,
  generatePacketFlags,
  parseQuestionRecords,
  parseQuestionRecord,
  generateQuestionRecords,
  generateQuestionRecord,
  parseResourceRecords,
  parseResourceRecord,
  generateResourceRecords,
  generateResourceRecord,
  generateTXTRecordData,
  generateSRVRecordData,
  isStringResourceRecord,
  isCachableResourceRecord,
};
