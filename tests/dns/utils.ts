import { fc } from '@fast-check/jest';
import { generateIPv6, parseIPv6 } from '@/dns';
import {
  PacketOpCode,
  PacketType,
  QClass,
  QType,
  RClass,
  RCode,
  RType,
} from '@/dns/types';

const uint32Arb = fc.integer({ min: 0, max: 4294967295 }); // 32-Bit Unsigned Integer Limits
const uint16Arb = fc.integer({ min: 0, max: 65535 }); // 16-Bit Unsigned Integer Limits

const packetOpCodeArb = fc.constantFrom(PacketOpCode.QUERY);
const rCodeArb = fc.constantFrom(RCode.NoError);

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

const questionRecordArb = fc.record({
  name: fc.domain(),
  type: qTypeArb,
  class: qClassArb,
  unicast: fc.boolean(),
});

const aaaaRecordArb = fc.record({
  name: fc.domain(),
  type: fc.constant(RType.AAAA),
  flush: fc.boolean(),
  class: fc.constant(RClass.IN),
  ttl: uint32Arb,
  data: fc
    .ipV6()
    .filter((ip) => ip.indexOf('.') === -1)
    .chain((ip) => fc.constant(parseIPv6(generateIPv6(ip)).data)),
  // Filter out mapped ipv6 addresses
});

const aRecordArb = fc.record({
  name: fc.domain(),
  type: fc.constant(RType.A),
  flush: fc.boolean(),
  class: fc.constant(RClass.IN),
  ttl: uint32Arb, // 32-bit Signed Integer Limits
  data: fc.ipV4(),
});

const cnamePtrRecordArb = fc.record({
  name: fc.domain(),
  type: fc.constantFrom(RType.CNAME, RType.PTR),
  flush: fc.boolean(),
  class: fc.constant(RClass.IN),
  ttl: uint32Arb,
  data: fc.domain(),
});

const txtRecordArb = fc.record({
  name: fc.domain(),
  type: fc.constant(RType.TXT),
  flush: fc.boolean(),
  class: fc.constant(RClass.IN),
  ttl: uint32Arb,
  data: fc.dictionary(
    fc
      .asciiString({ minLength: 1 })
      .filter((str) => str.indexOf('=') === -1 && str !== '__proto__'),
    fc.asciiString().filter((str) => str.indexOf('=') === -1),
  ),
});

const srvRecordArb = fc.record({
  name: fc.domain(),
  type: fc.constant(RType.SRV),
  flush: fc.boolean(),
  class: fc.constant(RClass.IN),
  ttl: uint32Arb,
  data: fc.record({
    priority: uint16Arb,
    weight: uint16Arb,
    port: uint16Arb,
    target: fc.domain(),
  }),
});

const resourceRecordArb = fc.oneof(
  aRecordArb,
  aaaaRecordArb,
  cnamePtrRecordArb,
  txtRecordArb,
  srvRecordArb,
);

const packetFlagsArb = fc.record({
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
});

const packetArb = fc.record({
  id: uint16Arb,
  flags: packetFlagsArb,
  questions: fc.array(questionRecordArb),
  additionals: fc.array(resourceRecordArb),
  answers: fc.array(resourceRecordArb),
  authorities: fc.array(resourceRecordArb),
});

export {
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
