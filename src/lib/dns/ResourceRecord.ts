import { DecodedData } from "./types";
import { decodeName, readUInt16BE, readUInt32BE } from "./utils";

const FLUSH_MASK = 0x8000; // 2 bytes, first bit set
const NOT_FLUSH_MASK = 0x7FFF;

export enum RType { // RFC 1035 3.2.2.
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

export enum RClass { // RFC 1035 3.2.4.
  IN = 1, // the internet
  // incomplete list
}

export type BaseRecord<T, D> = {
  name: string;
  type: T;
  class: RClass;

  flush: boolean;
  ttl: number;

  data: D;
}

const stringRecordTypes = [RType.A, RType.AAAA, RType.CNAME, RType.PTR, RType.TXT] as const;

export type StringRecordType = typeof stringRecordTypes[number];

export type StringRecord = BaseRecord<StringRecordType, string>;

export type TXTRecord = BaseRecord<RType.TXT, Map<string, string>>

export type SRVRecord = BaseRecord<RType.SRV, {
  port: number;
  target: string;
  priority: number;
  weight: number;
}>


// This will have to be fleshed out later
export type OptRecord = {
  type: RType.OPT;
  name: "0";

  udpPayloadSize: number; // RFC 6891 6.1.2. Class is used to denote "requestor's UDP payload size"
  extendedRCode: number; // RFC 6891 6.1.3. TTL is used to denote "extended RCODE and flags". First 8 bits are the extended RCODE.
  ednsVersion: number; // RFC 6891 6.1.3. Proceeding 8 bits are the Version.
  flags: number; // RFC 6891 6.1.4. Proceeding bit is the DO bit. For DNSSEC OK [RFC3225]. This is unneeded for mDNS. The proceeding 15 bits are set to zero and ignored.
  data: any[]; // RFC 6891 6.1.2. This makes up the RDATA field. Each option consists of an option-code, length of option-data in octets, and option-data.
}

export type NSECRecord = BaseRecord<RType.NSEC, {
  nextDomainName: string;
  rrTypeWindows: {
    windowId: number;
    bitmapSize: number;
    RRTypes: RType[];
  }[]
}>


export type ResourceRecord = StringRecord | TXTRecord | SRVRecord | OptRecord;

export const decodeResourceRecords = (buffer: Uint8Array, offset: number = 0, rrcount: number = 1): DecodedData<ResourceRecord[]> => {
  let totalReadBytes = 0;
  const records: ResourceRecord[] = [];
  while (totalReadBytes < buffer.byteLength && records.length < rrcount) {
    const totalReadBytesOffset = offset + totalReadBytes;

    const { data: name, readBytes } = decodeName(buffer, totalReadBytesOffset);

    let flush = false;

    const type = readUInt16BE(buffer, totalReadBytesOffset + readBytes);
    let rclass = readUInt16BE(buffer, totalReadBytesOffset + readBytes + 2);

    // Flush bit cannot exist on OPT records
    if (type !== RType.OPT) {
      flush = Boolean(rclass & FLUSH_MASK);
      rclass = (rclass & NOT_FLUSH_MASK);
    }

    const ttl = readUInt32BE(buffer, totalReadBytesOffset + readBytes + 4);
    const rdlength = readUInt16BE(buffer, totalReadBytesOffset + readBytes + 8);


    const dataOffset = totalReadBytesOffset + readBytes + 10;

    if (stringRecordTypes.includes(type)) {
      const sliecedStringDataBuffer = buffer.slice(dataOffset, dataOffset + rdlength);

      let data: string;
      if (type === RType.A) data = sliecedStringDataBuffer.join(".");
      if (type === RType.AAAA) data = decodeIPv6(sliecedStringDataBuffer);
      else data = decodeName(sliecedStringDataBuffer, 0).data;

      const stringRecord: StringRecord = {
        name,
        type,
        class: rclass,
        flush,
        ttl,
        data
      }
      records.push(stringRecord)
    }

    totalReadBytes += readBytes + 10 + rdlength;
  }

  return {
    data: records,
    readBytes: totalReadBytes,
  }
}

const decodeIPv6 = (buffer: Uint8Array): string => {
  if (buffer.length !== 16) {
    throw new Error('Invalid IPv6 address length');
  }

  const parts: string[] = [];

  for (let i = 0; i < buffer.length; i += 2) {
    const hexPart = (buffer[i] << 8) + buffer[i + 1];
    parts.push(hexPart.toString(16));
  }

  return parts.join(':');
}
