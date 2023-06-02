import {
  DecodedData,
  OpCode,
  Packet,
  PacketFlags,
  Question,
  RType,
  RClass,
  RCode,
  ResourceRecord,
  StringRecord,
  TXTRecord,
  SRVRecordData,
} from './types';

// Packet Flag Masks
const AUTHORITATIVE_ANSWER_MASK = 0x400;
const TRUNCATION_MASK = 0x200;
const RECURSION_DESIRED_MASK = 0x100;
const RECURSION_AVAILABLE_MASK = 0x80;
const ZERO_HEADER_MASK = 0x40;
const AUTHENTIC_DATA_MASK = 0x20;
const CHECKING_DISABLED_MASK = 0x10;

// RR masks
const FLUSH_MASK = 0x8000; // 2 bytes, first bit set
const NOT_FLUSH_MASK = 0x7fff;

function concatUInt8Array(...arrays: Uint8Array[]) {
  let totalLength = arrays.reduce((acc, val) => acc + val.byteLength, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.byteLength;
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
function parseLabels(input: Uint8Array, original: Uint8Array, compression: boolean = true): DecodedData<string> {
  let currentIndex = 0;
  let label = '';
  let readBytes = 0;

  let foundInitialPointer = false;
  let currentBuffer = input;

  while (currentBuffer[currentIndex] !== 0 && currentIndex < currentBuffer.byteLength) {
    if ((currentBuffer[currentIndex] & 0xc0) === 0xc0 && compression) {
      const dv = new DataView(currentBuffer.buffer, currentBuffer.byteOffset);
      const pointerOffset = dv.getUint16(currentIndex, false) & 0x3fff;

      foundInitialPointer = true; // The initial, or outermost pointer has been found
      currentBuffer = original; // set the currentBuffer to the original buffer to get the full scope of the packet
      currentIndex = pointerOffset; // set the currentIndex to the offset of the pointer in relation to the original buffer that is passed in
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

  if (!foundInitialPointer) readBytes += 1; // Include the terminating null byte if the pointer has not been found
  else readBytes += 2;

  return { data: label.slice(0, -1), remainder: input.subarray(readBytes) };
}

// Revisit this later...
function generateLabels(input: string, terminator: number[] = [0]): Uint8Array {
  const labels = input.split('.');
  const encodedName: number[] = [];

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

function toIPv6(buffer: Uint8Array, offset: number = 0): string {
  const dv = new DataView(buffer.buffer, buffer.byteOffset + offset);
  const parts: string[] = [];

  for (let i = 0; i < 16; i += 2) {
    const value = dv.getUint16(i, false).toString(16);
    parts.push(value);
  }

  return parts.join(':');
}

function fromIPv6(ip: string): Uint8Array {
  const parts = ip.split(':');

  const buffer = new Uint8Array(16);

  let offset = 0;
  for (const part of parts) {
    const hexPart = parseInt(part, 16);

    const encoded = encodeUInt16BE(hexPart);
    buffer.set(encoded, offset);
    offset += 2;
  }

  return buffer;
}

function parsePacket(input: Uint8Array, original: Uint8Array): Packet {
  const dv = new DataView(input.buffer, input.byteOffset);

  let inputBuffer = input.subarray(12); // Skip the header

  const id = dv.getUint16(0, false);
  const flags = dv.getUint16(2, false);
  const qdcount = dv.getUint16(4, false); // Question Count
  const ancount = dv.getUint16(6, false); // Answer Count
  const nscount = dv.getUint16(8, false); // Authority Count
  const arcount = dv.getUint16(10, false); // Additional Count

  const { data: questions, remainder } = parseQuestions(inputBuffer, original, qdcount);
  inputBuffer = remainder;

  return {
    id,
    flags: toPacketFlags(flags),
    questions,
    answers: [],
    additional: []
  };
}

function fromPacket(packet: Packet): Uint8Array {
  // todo
  return new Uint8Array();
}

function toPacketFlags(flags: number): PacketFlags {
  return {
    type: flags >> 15,
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

function fromPacketFlags(flags: PacketFlags): number {
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

function parseQuestions(
  input: Uint8Array,
  original: Uint8Array,
  qdcount: number = 1,
): DecodedData<Question[]> {
  let inputBuffer = input;

  const questions: Question[] = [];

  while (inputBuffer.byteLength !== 0 && questions.length < qdcount) {

    const { data: name, remainder } = parseLabels(inputBuffer, original);
    inputBuffer = remainder;

    // Remember, will error if out of bounds or running for too long, handle this later
    const dv = new DataView(remainder.buffer, remainder.byteOffset);
    questions.push({
      name,
      type: dv.getUint16(0, false),
      class: dv.getUint16(2, false),
    });

    inputBuffer = inputBuffer.subarray(4);
  }

  return {
    data: questions,
    remainder: inputBuffer,
  };
}

function generateQuestions(questions: Question[]): Uint8Array {
  const encodedQuestions: number[] = [];
  for (const question of questions) {
    const encodedName = generateLabels(question.name);
    // Implement Name Compression Later
    encodedQuestions.push(...encodedName);
    encodedQuestions.push((question.type >> 8) & 0xff, question.type & 0xff);
    encodedQuestions.push((question.class >> 8) & 0xff, question.class & 0xff);
  }
  return new Uint8Array(encodedQuestions);
}

function parseResourceRecords(
  input: Uint8Array,
  original: Uint8Array,
  rrcount: number = 1,
): DecodedData<ResourceRecord[]> {
  let inputBuffer = input;

  const records: ResourceRecord[] = [];

  while (inputBuffer.byteLength !== 0 && records.length < rrcount) {
    const { data: name, remainder } = parseLabels(inputBuffer, original);
    inputBuffer = remainder;

    const dv = new DataView(inputBuffer.buffer, inputBuffer.byteOffset);

    let flush = false;

    const type: RType = dv.getUint16(0, false);
    let rclass: RClass = dv.getUint16(2, false);

    // Flush bit cannot exist on OPT records
    if (type !== RType.OPT) {
      flush = Boolean(rclass & FLUSH_MASK);
      rclass = rclass & NOT_FLUSH_MASK;
    }

    const ttl = dv.getUint32(4, false);
    const rdlength = dv.getUint16(8, false);

    const slicedRDataBuffer = remainder.subarray(
      10,
      10 + rdlength,
    );

    let resourceRecord: ResourceRecord;

    if (isStringRType(type)) {

      let data: string;
      if (type === RType.A) data = slicedRDataBuffer.join('.');
      else if (type === RType.AAAA) data = toIPv6(slicedRDataBuffer);
      else data = parseLabels(slicedRDataBuffer, original).data;

      resourceRecord = {
        name,
        type,
        class: rclass,
        flush,
        ttl,
        data
      };
    } else if (type === RType.TXT) {
      resourceRecord = {
        name,
        type,
        class: rclass,
        flush,
        ttl,
        data: parseTXTRecordData(slicedRDataBuffer, rdlength).data,
      };
    } else if (type == RType.SRV) {
      resourceRecord = {
        name,
        type,
        class: rclass,
        flush,
        ttl,
        data: parseSRVRecordData(slicedRDataBuffer, original, rdlength).data,
      };
    } else {
      // Todo, SRV, OPT, NSEC etc
      resourceRecord = {
        name,
        type: RType.A,
        class: rclass,
        flush,
        ttl,
        data: "",
      };
    }

    records.push(resourceRecord);
    inputBuffer = inputBuffer.subarray(10 + rdlength);
  }


  return {
    data: records,
    remainder: inputBuffer,
  };
}

function parseTXTRecordData(input: Uint8Array, rdlength: number = input.byteLength): DecodedData<Record<string, string>> {
  let inputBuffer = input.subarray(0, rdlength);
  const txtAttributes: Record<string, string> = {};

  while (inputBuffer.byteLength !== 0) {
    const textLength = inputBuffer[0];
    const decodedPair = new TextDecoder().decode(inputBuffer.subarray(1, textLength + 1));

    const [key, value] = decodedPair.split('=');

    txtAttributes[key] = typeof value !== "undefined" ? value : "";
    inputBuffer = inputBuffer.subarray(textLength + 1);
  }

  return {
    data: txtAttributes,
    remainder: input.subarray(rdlength),
  };
}

function parseSRVRecordData(input: Uint8Array, original: Uint8Array, rdlength: number = input.byteLength): DecodedData<SRVRecordData> {
  const dv = new DataView(input.buffer, input.byteOffset);
  const priority = dv.getUint16(0, false);
  const weight = dv.getUint16(2, false);
  const port = dv.getUint16(4, false);

  const target = parseLabels(input.subarray(6), original);

  return {
    data: {
      port,
      priority,
      weight,
      target: target.data,
    },
    remainder: input.subarray(rdlength),
  }
}

function generateResourceRecords(records: ResourceRecord[]): Uint8Array {
  const buffer = new Uint8Array();
  for (const record of records) {
    // Implement Name Compression Later
    const encodedName = generateLabels(record.name);

    let rdata: Uint8Array;
    if (isStringRecord(record)) {
      if (record.type === RType.A) {
        rdata = new Uint8Array(record.data.split('.').map((v) => Number(v)));
      }
      else if (record.type === RType.AAAA) {
        rdata = fromIPv6(record.data);
      }
      else {
        rdata = generateLabels(record.data);
      }
    }
    else if (record.type === RType.TXT) {
      rdata = generateTXTRecordData(record.data);
    }
    else {
      rdata = new Uint8Array();
    }

  }
  return buffer;
}

function generateTXTRecordData(data: Record<string, string>): Uint8Array {
  const encodedAttributes = Object.entries(data).flatMap(([key, val]) => {
    const encodedPair = new TextEncoder().encode(`${key}=${val}`);
    return [encodedPair.length, ...encodedPair];
  });
  return new Uint8Array(encodedAttributes);
}

function generateSRVRecordData(data: SRVRecordData): Uint8Array {
  const buffer = new Uint8Array(6);
  const dv = new DataView(buffer.buffer);

  dv.setUint16(0, data.priority, false);
  dv.setUint16(2, data.weight, false);
  dv.setUint16(4, data.port, false);

  return concatUInt8Array(buffer, generateLabels(data.target));
}

function isStringRecord(record: ResourceRecord): record is StringRecord {
  return isStringRType(record.type);
}

function isStringRType(type: RType): type is StringRecord['type'] {
  return [
    RType.A,
    RType.AAAA,
    RType.CNAME,
    RType.PTR,
  ].includes(type);
}

export {
  concatUInt8Array,
  encodeUInt16BE,
  encodeUInt32BE,
  parseLabels,
  generateLabels,
  toIPv6,
  fromIPv6,
  parsePacket,
  toPacketFlags,
  fromPacketFlags,
  parseQuestions,
  generateQuestions,
  parseResourceRecords,
  generateResourceRecords,
  generateTXTRecordData,
  generateSRVRecordData
};
