export interface DecodedData<T> {
  data: T;
  readBytes: number;
}

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

export interface ResourceRecord {
  name: string;
  type: RType;
  flush: boolean;
  class: RClass;
  ttl: number;
  data: any;

  getDataLength(): () => number;
}
