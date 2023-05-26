interface DecodedData<T> {
  data: T;
  readBytes: number;
}

type Packet = {
  id: number;
  flags: PacketFlags;
  questions: Question[];
}

type PacketFlags = {
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

enum PacketType {
  QUERY = 0,
  RESPONSE = 1, // 16th bit set
}

enum OpCode { // RFC 6895 2.2.
  QUERY = 0,
  // incomplete list
}

enum RCode { // RFC 6895 2.3.
  NoError = 0,
  // incomplete list
}


type Question = {
  name: string;
  type: QType;
  class: QClass;
}

enum QClass { // RFC 1035 3.2.4. 3.2.5.
  IN = 1, // the internet
  ANY = 255,
  // incomplete list
}

enum QType { // RFC 1035 3.2.2. 3.2.3.
  A = 1,
  CNAME = 5,
  PTR = 12,
  TXT = 16,
  AAAA = 28, // RFC 3596 2.1.
  SRV = 33, // RFC 2782
  OPT = 41, // RFC 6891
  NSEC = 47, // RFC 4034 4.
  ANY = 255,
  // incomplete list
}

type ResourceRecord = StringRecord | TXTRecord | SRVRecord | OptRecord | NSECRecord;

enum RType { // RFC 1035 3.2.2.
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

enum RClass { // RFC 1035 3.2.4.
  IN = 1, // the internet
  // incomplete list
}

type BaseRecord<T, D> = {
  name: string;
  type: T;
  class: RClass;

  flush: boolean;
  ttl: number;

  data: D;
}

type StringRecord = BaseRecord<RType.A | RType.AAAA | RType.CNAME | RType.PTR, string>;

type TXTRecord = BaseRecord<RType.TXT, Map<string, string>>

type SRVRecord = BaseRecord<RType.SRV, {
  port: number;
  target: string;
  priority: number;
  weight: number;
}>

// This will have to be fleshed out later
type OptRecord = {
  type: RType.OPT;
  name: "0";

  udpPayloadSize: number; // RFC 6891 6.1.2. Class is used to denote "requestor's UDP payload size"
  extendedRCode: number; // RFC 6891 6.1.3. TTL is used to denote "extended RCODE and flags". First 8 bits are the extended RCODE.
  ednsVersion: number; // RFC 6891 6.1.3. Proceeding 8 bits are the Version.
  flags: number; // RFC 6891 6.1.4. Proceeding bit is the DO bit. For DNSSEC OK [RFC3225]. This is unneeded for mDNS. The proceeding 15 bits are set to zero and ignored.
  data: any[]; // RFC 6891 6.1.2. This makes up the RDATA field. Each option consists of an option-code, length of option-data in octets, and option-data.
}

type NSECRecord = BaseRecord<RType.NSEC, {
  nextDomainName: string;
  rrTypeWindows: {
    windowId: number;
    bitmapSize: number;
    RRTypes: RType[];
  }[]
}>

export {
  DecodedData,

  Packet,

  PacketFlags,
  PacketType,
  OpCode,
  RCode,

  Question,
  QClass,
  QType,

  ResourceRecord,
  RType,
  RClass,
  BaseRecord,
  StringRecord,
  TXTRecord,
  SRVRecord,
  OptRecord,
  NSECRecord,
}
