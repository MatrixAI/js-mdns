import type { Hostname, Port } from '#types.js';
import { fc } from '@fast-check/jest';
import {
  PacketOpCode,
  PacketType,
  QClass,
  QType,
  RClass,
  RCode,
  RType,
  generateIPv6,
  parseIPv6,
} from '#dns/index.js';

const uint32Arb = fc.integer({ min: 0, max: 4294967295 }); // 32-Bit Unsigned Integer Limits
const uint16Arb = fc.integer({ min: 0, max: 65535 }); // 16-Bit Unsigned Integer Limits

const packetOpCodeArb = fc.constantFrom(PacketOpCode.QUERY);
const rCodeArb = fc.constantFrom(RCode.NoError);

const domainArb: fc.Arbitrary<Hostname> = fc.domain() as fc.Arbitrary<Hostname>;
const portArb = uint16Arb as fc.Arbitrary<Port>;

// For all integers in set of values in QType/QClass
const qTypeArb = fc.constantFrom(
  QType.A,
  QType.AAAA,
  QType.ANY,
  QType.CNAME,
  QType.NSEC,
  QType.OPT,
  QType.PTR,
  QType.TXT,
  QType.SRV,
);
const qClassArb = fc.constantFrom(QClass.ANY, QClass.IN);

const questionRecordArb: fc.Arbitrary<{
  name: Hostname;
  type: QType;
  class: QClass;
  unicast: boolean;
}> = fc.record(
  {
    name: domainArb,
    type: qTypeArb,
    class: qClassArb,
    unicast: fc.boolean(),
  },
  { noNullPrototype: true },
);

const aaaaRecordArb: fc.Arbitrary<{
  name: Hostname;
  type: RType.AAAA;
  flush: boolean;
  class: RClass.IN;
  ttl: number;
  data: string;
}> = fc.record(
  {
    name: domainArb,
    type: fc.constant(RType.AAAA),
    flush: fc.boolean(),
    class: fc.constant(RClass.IN),
    ttl: uint32Arb,
    data: fc
      .ipV6()
      .filter((ip) => ip.indexOf('.') === -1)
      .chain((ip) => fc.constant(parseIPv6(generateIPv6(ip)).data)),
    // Filter out mapped ipv6 addresses
  },
  { noNullPrototype: true },
);

const aRecordArb: fc.Arbitrary<{
  name: Hostname;
  type: RType.A;
  flush: boolean;
  class: RClass.IN;
  ttl: number; // 32-bit Signed Integer Limits
  data: string;
}> = fc.record(
  {
    name: domainArb,
    type: fc.constant(RType.A),
    flush: fc.boolean(),
    class: fc.constant(RClass.IN),
    ttl: uint32Arb, // 32-bit Signed Integer Limits
    data: fc.ipV4(),
  },
  { noNullPrototype: true },
);

const cnamePtrRecordArb: fc.Arbitrary<{
  name: Hostname;
  type: RType.CNAME | RType.PTR;
  flush: boolean;
  class: RClass.IN;
  ttl: number;
  data: Hostname;
}> = fc.record(
  {
    name: domainArb,
    type: fc.constantFrom(RType.CNAME, RType.PTR),
    flush: fc.boolean(),
    class: fc.constant(RClass.IN),
    ttl: uint32Arb,
    data: domainArb,
  },
  { noNullPrototype: true },
);

const txtRecordArb: fc.Arbitrary<{
  name: Hostname;
  type: RType.TXT;
  flush: boolean;
  class: RClass.IN;
  ttl: number;
  data: Record<string, unknown>;
}> = fc.record(
  {
    name: domainArb,
    type: fc.constant(RType.TXT),
    flush: fc.boolean(),
    class: fc.constant(RClass.IN),
    ttl: uint32Arb,
    data: fc.dictionary(
      fc
        .string({ minLength: 1 })
        .filter((str) => str.indexOf('=') === -1 && str !== '__proto__'),
      fc.string().filter((str) => str.indexOf('=') === -1),
    ),
  },
  { noNullPrototype: true },
);

const srvRecordArb: fc.Arbitrary<{
  name: Hostname;
  type: RType.SRV;
  flush: boolean;
  class: RClass.IN;
  ttl: number;
  data: {
    priority: number;
    weight: number;
    port: Port;
    target: Hostname;
  };
}> = fc.record(
  {
    name: domainArb,
    type: fc.constant(RType.SRV),
    flush: fc.boolean(),
    class: fc.constant(RClass.IN),
    ttl: uint32Arb,
    data: fc.record(
      {
        priority: uint16Arb,
        weight: uint16Arb,
        port: portArb,
        target: domainArb,
      },
      { noNullPrototype: true },
    ),
  },
  { noNullPrototype: true },
);

const resourceRecordArb = fc.oneof(
  aRecordArb,
  aaaaRecordArb,
  cnamePtrRecordArb,
  txtRecordArb,
  srvRecordArb,
);

const packetFlagsArb = fc.record(
  {
    type: fc.constantFrom(PacketType.QUERY, PacketType.RESPONSE),
    opcode: packetOpCodeArb,
    rcode: rCodeArb,
    authoritativeAnswer: fc.boolean(),
    truncation: fc.boolean(),
    recursionDesired: fc.boolean(),
    recursionAvailable: fc.boolean(),
    zero: fc.boolean(),
    authenticData: fc.boolean(),
    checkingDisabled: fc.boolean(),
  },
  { noNullPrototype: true },
);

const packetArb = fc.record(
  {
    id: uint16Arb,
    flags: packetFlagsArb,
    questions: fc.array(questionRecordArb),
    additionals: fc.array(resourceRecordArb),
    answers: fc.array(resourceRecordArb),
    authorities: fc.array(resourceRecordArb),
  },
  { noNullPrototype: true },
);

export {
  domainArb,
  portArb,
  packetOpCodeArb,
  rCodeArb,
  qTypeArb,
  qClassArb,
  questionRecordArb,
  aaaaRecordArb,
  aRecordArb,
  cnamePtrRecordArb,
  txtRecordArb,
  srvRecordArb,
  resourceRecordArb,
  packetFlagsArb,
  packetArb,
};
