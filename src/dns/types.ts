interface Parsed<T> {
  data: T;
  remainder: Uint8Array;
}

type Packet = {
  id: number;
  flags: PacketFlags;
  questions: Array<QuestionRecord>;
  answers: ResourceRecord[];
  authorities: ResourceRecord[];
  additionals: ResourceRecord[];
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

type QuestionRecord = {
  name: string;
  type: QType;
  class: QClass;
  unicast?: boolean;
};

const enum QClass { // RFC 1035 3.2.4. 3.2.5.
  IN = 1, // The internet
  ANY = 255,
}

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

type CachableResourceRecord = StringRecord | TXTRecord | SRVRecord | NSECRecord;

type ResourceRecord = CachableResourceRecord | OPTRecord;

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

const enum RClass { // RFC 1035 3.2.4.
  IN = 1, // The internet
  // incomplete list
}

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

type OPTRecord = BaseResourceRecord<RType.OPT, any[]> & {
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
    rrTypeWindows: {
      windowId: number;
      bitmapSize: number;
      RRTypes: RType[];
    }[];
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
export { PacketOpCode, PacketType, RCode, RType, RClass, QClass, QType };
