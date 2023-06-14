import { fc, testProp } from '@fast-check/jest';
import {
  concatUInt8Array,
  ErrorDNSParse,
  generateIPv6,
  generateLabels,
  generatePacket,
  generatePacketFlags,
  generateQuestionRecords,
  generateResourceRecords,
  PacketOpCode,
  PacketType,
  parseIPv6,
  parseLabels,
  parsePacket,
  parsePacketFlags,
  parseQuestionRecords,
  parseResourceRecords,
  QClass,
  QType,
  RClass,
  RCode,
  ResourceRecord,
  RType,
} from '@/dns';

const FC_UINT32 = fc.integer({ min: 0, max: 4294967295 }); // 32-Bit Unsigned Integer Limits
const FC_UINT16 = fc.integer({ min: 0, max: 65535 }); // 16-Bit Unsigned Integer Limits

const FC_PACKET_OPCODES = fc.constantFrom(PacketOpCode.QUERY);
const FC_RCODES = fc.constantFrom(RCode.NoError);

// For all integers in set of values in QType/QClass
const FC_QTYPES = fc.constantFrom(
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
const FC_QCLASSES = fc.constantFrom(QClass.ANY, QClass.IN);

const FC_QUESTION = fc.record({
  name: fc.domain(),
  type: FC_QTYPES,
  class: FC_QCLASSES,
  unicast: fc.boolean(),
});

const FC_AAAA_RECORD = fc.record({
  name: fc.domain(),
  type: fc.constant(RType.AAAA),
  flush: fc.boolean(),
  class: fc.constant(RClass.IN),
  ttl: FC_UINT32,
  data: fc
    .ipV6()
    .chain((ip) =>
      fc.constant(parseIPv6(generateIPv6('0:0:0:0:0:0:0:0')).data),
    ),
});

const FC_A_RECORD = fc.record({
  name: fc.domain(),
  type: fc.constant(RType.A),
  flush: fc.boolean(),
  class: fc.constant(RClass.IN),
  ttl: FC_UINT32, // 32-bit Signed Integer Limits
  data: fc.ipV4(),
});

const FC_CNAME_PTR_RECORD = fc.record({
  name: fc.domain(),
  type: fc.constantFrom(RType.CNAME, RType.PTR),
  flush: fc.boolean(),
  class: fc.constant(RClass.IN),
  ttl: FC_UINT32,
  data: fc.domain(),
});

const FC_TXT_RECORD = fc.record({
  name: fc.domain(),
  type: fc.constant(RType.TXT),
  flush: fc.boolean(),
  class: fc.constant(RClass.IN),
  ttl: FC_UINT32,
  data: fc.dictionary(fc.unicodeString(), fc.unicodeString()),
});

const FC_SRV_RECORD = fc.record({
  name: fc.domain(),
  type: fc.constant(RType.SRV),
  flush: fc.boolean(),
  class: fc.constant(RClass.IN),
  ttl: FC_UINT32,
  data: fc.record({
    priority: FC_UINT16,
    weight: FC_UINT16,
    port: FC_UINT16,
    target: fc.domain(),
  }),
});

const FC_RESOURCE_RECORD = fc.oneof(
  FC_AAAA_RECORD,
  FC_A_RECORD,
  FC_CNAME_PTR_RECORD,
  FC_TXT_RECORD,
  FC_SRV_RECORD,
);

const FC_PACKET_FLAGS = fc.record({
  type: fc.constantFrom(PacketType.QUERY, PacketType.RESPONSE),
  opcode: FC_PACKET_OPCODES,
  rcode: FC_RCODES,
  authoritativeAnswer: fc.boolean(),
  truncation: fc.boolean(),
  recursionDesired: fc.boolean(),
  recursionAvailable: fc.boolean(),
  zero: fc.boolean(),
  authenticData: fc.boolean(),
  checkingDisabled: fc.boolean(),
});

describe('/dns/utils.ts', () => {
  testProp('labels', [fc.domain()], (domain) => {
    const generatedLabels = generateLabels(domain);
    const labels = parseLabels(generatedLabels, generatedLabels, false);
    expect(labels.data).toEqual(domain);
  });
  testProp('labels pointer post-label', [fc.domain()], (domain) => {
    const generatedLabelsDomain = generateLabels(domain);
    const generatedLabels = concatUInt8Array(
      generatedLabelsDomain,
      new Uint8Array([0xc0, 0x00]),
    );
    const labels = parseLabels(
      generatedLabels.subarray(generatedLabelsDomain.length),
      generatedLabels,
      true,
    );
    expect(labels.data).toEqual(domain);
  });
  testProp('labels pointer pre-label', [fc.domain()], (domain) => {
    const generatedLabelsDomain = generateLabels(domain);
    const generatedLabels = concatUInt8Array(
      new Uint8Array([0xc0, 0x02]),
      generatedLabelsDomain,
    );
    const labels = parseLabels(generatedLabels, generatedLabels, true);
    expect(labels.data).toEqual(domain);
  });
  testProp(
    'labels pointer terminated label',
    [fc.domain(), fc.domain()],
    (domain1, domain2) => {
      const generatedLabelsDomain1 = generateLabels(domain1);
      const generatedLabelsDomain2 = generateLabels(domain2, [0xc0, 0x00]);
      const generatedLabels = concatUInt8Array(
        generatedLabelsDomain1,
        generatedLabelsDomain2,
      );
      const labels = parseLabels(
        generatedLabels.subarray(generatedLabelsDomain1.length),
        generatedLabels,
        true,
      );
      expect(labels.data).toEqual(domain2 + '.' + domain1);
    },
  );
  testProp('labels pointer recursion', [fc.domain()], (domain) => {
    const generatedLabels = generateLabels(domain, [0xc0, 0x00]);
    const parser = () => {
      parseLabels(generatedLabels, generatedLabels, true);
    };
    expect(parser).toThrow(ErrorDNSParse);
  });
  testProp('questions', [fc.array(FC_QUESTION)], (questions) => {
    const generatedQuestions = generateQuestionRecords(questions);
    const parsedQuestions = parseQuestionRecords(
      generatedQuestions,
      generatedQuestions,
      questions.length,
    );
    expect(parsedQuestions.data).toEqual(questions);
  });
  testProp(
    'packet flags',
    [
      fc.record({
        type: fc.constantFrom(PacketType.QUERY, PacketType.RESPONSE),
        opcode: FC_PACKET_OPCODES,
        rcode: FC_RCODES,
        authoritativeAnswer: fc.boolean(),
        truncation: fc.boolean(),
        recursionDesired: fc.boolean(),
        recursionAvailable: fc.boolean(),
        zero: fc.boolean(),
        authenticData: fc.boolean(),
        checkingDisabled: fc.boolean(),
      }),
    ],
    (flags) => {
      const encodedFlags = generatePacketFlags(flags);
      const decodedFlags = parsePacketFlags(encodedFlags);
      expect(decodedFlags.data).toEqual(flags);
    },
  );
  testProp('resource records a', [fc.array(FC_A_RECORD)], (resourceRecords) => {
    const generatedResourceRecords = generateResourceRecords(
      resourceRecords as any,
    );
    const parsedResourceRecords = parseResourceRecords(
      generatedResourceRecords,
      generatedResourceRecords,
      resourceRecords.length,
    );
    expect(parsedResourceRecords.data).toEqual(resourceRecords);
  });
  testProp(
    'resource records aaaa',
    [fc.array(FC_AAAA_RECORD)],
    (resourceRecords) => {
      const generatedResourceRecords = generateResourceRecords(
        resourceRecords as any,
      );
      const parsedResourceRecords = parseResourceRecords(
        generatedResourceRecords,
        generatedResourceRecords,
        resourceRecords.length,
      );
      expect(parsedResourceRecords.data).toEqual(resourceRecords);
    },
  );
  testProp(
    'resource records aaaa',
    [fc.array(FC_AAAA_RECORD)],
    (resourceRecords) => {
      const generatedResourceRecords = generateResourceRecords(
        resourceRecords as any,
      );
      const parsedResourceRecords = parseResourceRecords(
        generatedResourceRecords,
        generatedResourceRecords,
        resourceRecords.length,
      );
      expect(parsedResourceRecords.data).toEqual(resourceRecords);
    },
  );
  testProp(
    'resource records cname ptr',
    [fc.array(FC_CNAME_PTR_RECORD)],
    (resourceRecords) => {
      const generatedResourceRecords = generateResourceRecords(
        resourceRecords as any,
      );
      const parsedResourceRecords = parseResourceRecords(
        generatedResourceRecords,
        generatedResourceRecords,
        resourceRecords.length,
      );
      expect(parsedResourceRecords.data).toEqual(resourceRecords);
    },
  );
  testProp(
    'resource records srv',
    [fc.array(FC_SRV_RECORD)],
    (resourceRecords) => {
      const generatedResourceRecords = generateResourceRecords(
        resourceRecords as any,
      );
      const parsedResourceRecords = parseResourceRecords(
        generatedResourceRecords,
        generatedResourceRecords,
        resourceRecords.length,
      );
      expect(parsedResourceRecords.data).toEqual(resourceRecords);
    },
  );
  testProp(
    'resource records txt',
    [fc.array(FC_TXT_RECORD)],
    (resourceRecords) => {
      const generatedResourceRecords = generateResourceRecords(
        resourceRecords as any,
      );
      const parsedResourceRecords = parseResourceRecords(
        generatedResourceRecords,
        generatedResourceRecords,
        resourceRecords.length,
      );
      expect(parsedResourceRecords.data).toEqual(resourceRecords);
    },
  );
  testProp('packet flags', [FC_PACKET_FLAGS], (flags) => {
    const generatedFlags = generatePacketFlags(flags);
    const parsedFlags = parsePacketFlags(generatedFlags);
    expect(parsedFlags.data).toEqual(flags);
  });
  testProp(
    'packet',
    [
      fc.record({
        id: FC_UINT16,
        flags: FC_PACKET_FLAGS,
        questions: fc.array(FC_QUESTION),
        additionals: fc.array(FC_RESOURCE_RECORD),
        answers: fc.array(FC_RESOURCE_RECORD),
        authorities: fc.array(FC_RESOURCE_RECORD),
      }),
    ],
    (packet) => {
      const generatedPacket = generatePacket(packet as any);
      const parsedPacket = parsePacket(generatedPacket);
      expect(parsedPacket).toEqual(packet);
    },
  );
});
