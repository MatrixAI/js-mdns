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

function readUInt16BE(data: Uint8Array, offset: number = 0): number {
  return (data[offset] << 8) | data[offset + 1];
}

function encodeUInt16BE(value: number): Uint8Array {
  return new Uint8Array([(value >> 8) & 0xff, value & 0xff]);
}

function readUInt32BE(data: Uint8Array, offset: number = 0): number {
  return (
    (data[offset] << 24) |
    (data[offset + 1] << 16) |
    (data[offset + 2] << 8) |
    data[offset + 3]
  );
}

function encodeUInt32BE(value: number): Uint8Array {
  return new Uint8Array([
    (value >> 24) & 0xff,
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  ]);
}

// Remember, the whole packet needs to be fed into this function, as the pointer is relative to the start of the packet.
function toName(data: Uint8Array, offset: number = 0): DecodedData<string> {
  let currentIndex = offset;
  let name = '';
  let readBytes = 0;
  let foundPointer = false;

  while (data[currentIndex] !== 0) {
    if ((data[currentIndex] & 0xc0) === 0xc0) {
      const pointerOffset = readUInt16BE(data, currentIndex) & 0x3fff;
      currentIndex = pointerOffset;
      readBytes += 2; // Compression pointer occupies 2 bytes
      foundPointer = true;
    } else {
      const labelLength = data[currentIndex];
      const label = new TextDecoder().decode(
        data.subarray(currentIndex + 1, currentIndex + 1 + labelLength),
      );
      name += label + '.';
      currentIndex += labelLength + 1;
      if (!foundPointer) readBytes += labelLength + 1; // Label length + label characters occupy labelLength + 1 bytes
    }
  }

  if (!foundPointer) readBytes += 1; // Include the terminating null byte

  return { data: name.slice(0, -1), readBytes };
}

function fromName(name: string): Uint8Array {
  const labels = name.split('.');
  const encodedName: number[] = [];

  for (const label of labels) {
    if (label.length > 63) {
      throw new Error(
        `Label "${label}" exceeds the maximum length of 63 characters.`,
      );
    }

    encodedName.push(label.length);

    for (let i = 0; i < label.length; i++) {
      const codePoint = label.codePointAt(i);
      if (codePoint === undefined) {
        throw new Error(`Failed to retrieve code point for label "${label}".`);
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

  encodedName.push(0); // Terminating null byte

  return new Uint8Array(encodedName);
}

function toIPv6(buffer: Uint8Array, offset: number = 0): string {
  const parts: string[] = [];

  for (let i = offset; i < offset + 16; i += 2) {
    const value = readUInt16BE(buffer, i).toString(16);
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

    buffer[offset++] = hexPart >> 8;
    buffer[offset++] = hexPart & 0xff;
  }

  return buffer;
}

function toPacket(buffer: Uint8Array): Packet {
  const id = readUInt16BE(buffer, 0);
  const flags = readUInt16BE(buffer, 2);
  const qdcount = readUInt16BE(buffer, 4); // Question Count
  const ancount = readUInt16BE(buffer, 6); // Answer Count
  const nscount = readUInt16BE(buffer, 8); // Authority Count
  const arcount = readUInt16BE(buffer, 10); // Additional Count

  return {
    id,
    flags: toPacketFlags(flags),
    questions: toQuestions(buffer, 12, qdcount).data,
  };
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

function toQuestions(
  buffer: Uint8Array,
  offset: number = 0,
  qdcount: number = 1,
): DecodedData<Question[]> {
  let totalReadBytes = 0;
  const questions: Question[] = [];
  while (totalReadBytes < buffer.byteLength && questions.length < qdcount) {
    const totalReadBytesOffset = offset + totalReadBytes;

    const { data: name, readBytes } = toName(buffer, totalReadBytesOffset);
    questions.push({
      name,
      type: readUInt16BE(buffer, totalReadBytesOffset + readBytes),
      class: readUInt16BE(buffer, totalReadBytesOffset + readBytes + 2),
    });

    totalReadBytes += readBytes + 4;
  }
  return {
    data: questions,
    readBytes: totalReadBytes,
  };
}

function fromQuestions(questions: Question[]): Uint8Array {
  const encodedQuestions: number[] = [];
  for (const question of questions) {
    const encodedName = fromName(question.name);
    // Implement Name Compression Later
    encodedQuestions.push(...encodedName);
    encodedQuestions.push((question.type >> 8) & 0xff, question.type & 0xff);
    encodedQuestions.push((question.class >> 8) & 0xff, question.class & 0xff);
  }
  return new Uint8Array(encodedQuestions);
}

function toResourceRecords(
  buffer: Uint8Array,
  offset: number = 0,
  rrcount: number = 1,
): DecodedData<ResourceRecord[]> {
  let totalReadBytes = 0;
  const records: ResourceRecord[] = [];
  while (totalReadBytes < buffer.byteLength && records.length < rrcount) {
    const totalReadBytesOffset = offset + totalReadBytes;

    const { data: name, readBytes } = toName(buffer, totalReadBytesOffset);

    let flush = false;

    const type: RType = readUInt16BE(buffer, totalReadBytesOffset + readBytes);
    let rclass: RClass = readUInt16BE(buffer, totalReadBytesOffset + readBytes + 2);

    // Flush bit cannot exist on OPT records
    if (type !== RType.OPT) {
      flush = Boolean(rclass & FLUSH_MASK);
      rclass = rclass & NOT_FLUSH_MASK;
    }

    const ttl = readUInt32BE(buffer, totalReadBytesOffset + readBytes + 4);
    const rdlength = readUInt16BE(buffer, totalReadBytesOffset + readBytes + 8);

    const dataOffset = totalReadBytesOffset + readBytes + 10;

    if (isStringRType(type)) {
      const sliecedStringDataBuffer = buffer.subarray(
        dataOffset,
        dataOffset + rdlength,
      );

      let data: string;
      if (type === RType.A) data = sliecedStringDataBuffer.join('.');
      else if (type === RType.AAAA) data = toIPv6(sliecedStringDataBuffer);
      else data = toName(sliecedStringDataBuffer, 0).data;

      const stringRecord: StringRecord = {
        name,
        type,
        class: rclass,
        flush,
        ttl,
        data,
      };
      records.push(stringRecord);
    } else if (type === RType.TXT) {
      // ???
    } else if (type === RType.SRV) {
      // ???
    }

    totalReadBytes += readBytes + 10 + rdlength;
  }

  return {
    data: records,
    readBytes: totalReadBytes,
  };
}

function fromResourceRecords(records: ResourceRecord[]): Uint8Array {
  const buffer = new Uint8Array();
  for (const record of records) {
    // Implement Name Compression Later
    const encodedName = fromName(record.name);

    if (isStringRecord(record)) {
      let data: Uint8Array;
      if (record.type === RType.A) {
        data = new Uint8Array(record.data.split('.').map((v) => Number(v)));
      }
      else if (record.type === RType.AAAA) {
        data = fromIPv6(record.data);
      }
      else {
        data = fromName(record.data);
      }
    }

  }
  return buffer;
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
  readUInt16BE,
  encodeUInt16BE,
  readUInt32BE,
  encodeUInt32BE,
  toName,
  fromName,
  toIPv6,
  fromIPv6,
  toPacket,
  toPacketFlags,
  fromPacketFlags,
  toQuestions,
  fromQuestions,
  toResourceRecords,
};
