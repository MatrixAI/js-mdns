import type {
  PacketOpCode,
  PacketType,
  RType,
  RCode,
  RClass,
  QType,
  QClass,
} from './utils';

interface Parsed<T> {
  data: T;
  remainder: Uint8Array;
}

type Packet = {
  id: number;
  flags: PacketFlags;
  questions: Array<QuestionRecord>;
  answers: Array<ResourceRecord>;
  authorities: Array<ResourceRecord>;
  additionals: Array<ResourceRecord>;
};

type PacketHeader = {
  id: number;
  flags: PacketFlags;
  qdcount: number; // Question
  ancount: number; // Answer
  nscount: number; // Authority
  arcount: number; // Additional
};

type PacketFlags = {
  // Always Present
  type: PacketType;
  opcode: PacketOpCode;
  rcode: RCode;

  authoritativeAnswer?: boolean;
  truncation?: boolean;

  // Below flags are all not used with mdns
  recursionDesired?: boolean;
  recursionAvailable?: boolean;
  zero?: boolean;
  authenticData?: boolean;
  checkingDisabled?: boolean;
};

type QuestionRecord = {
  name: string;
  type: QType;
  class: QClass;
  unicast?: boolean;
};

type CachableResourceRecord = StringRecord | TXTRecord | SRVRecord | NSECRecord;

type ResourceRecord = CachableResourceRecord | OPTRecord;

type BaseResourceRecord<T, D> = {
  name: string;
  type: T;
  class: RClass;

  flush?: boolean;
  ttl: number;

  data: D;
};

type StringRecord = BaseResourceRecord<
  RType.A | RType.AAAA | RType.CNAME | RType.PTR,
  string
>;

type TXTRecord = BaseResourceRecord<RType.TXT, Record<string, string>>;

type TXTRecordValue = Record<string, string>;

type SRVRecord = BaseResourceRecord<RType.SRV, SRVRecordValue>;

type SRVRecordValue = {
  port: number;
  target: string;
  priority: number;
  weight: number;
};

type OPTRecord = BaseResourceRecord<RType.OPT, Array<any>> & {
  name: '0';
  ttl: 0;
  flush: false;

  udpPayloadSize: number; // RFC 6891 6.1.2. Class is used to denote "requestor's UDP payload size"
  extendedRCode: number; // RFC 6891 6.1.3. TTL is used to denote "extended RCODE and flags". First 8 bits are the extended RCODE.
  ednsVersion: number; // RFC 6891 6.1.3. Proceeding 8 bits are the Version.
  flags: number; // RFC 6891 6.1.4. Proceeding bit is the DO bit. For DNSSEC OK [RFC3225]. This is unneeded for mDNS. The proceeding 15 bits are set to zero and ignored.
};

type NSECRecord = BaseResourceRecord<
  RType.NSEC,
  {
    nextDomainName: string;
    rrTypeWindows: Array<{
      windowId: number;
      bitmapSize: number;
      RRTypes: Array<RType>;
    }>;
  }
>;

export type {
  Parsed,
  Packet,
  PacketHeader,
  PacketFlags,
  QuestionRecord,
  CachableResourceRecord,
  ResourceRecord,
  BaseResourceRecord,
  StringRecord,
  TXTRecord,
  TXTRecordValue,
  SRVRecord,
  SRVRecordValue,
  OPTRecord,
  NSECRecord,
};
