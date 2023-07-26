import { fc, testProp } from '@fast-check/jest';
import {
  concatUInt8Array,
  ErrorDNSParse,
  generateLabels,
  generatePacket,
  generatePacketFlags,
  generateQuestionRecords,
  generateResourceRecords,
  parseLabels,
  parsePacket,
  parsePacketFlags,
  parseQuestionRecords,
  parseResourceRecords,
} from '@/dns';
import {
  aaaaRecordArb,
  aRecordArb,
  cnamePtrRecordArb,
  domainArb,
  packetArb,
  packetFlagsArb,
  questionRecordArb,
  srvRecordArb,
  txtRecordArb,
} from './utils';

describe('dns packet parser/generator', () => {
  testProp('labels', [domainArb], (domain) => {
    const generatedLabels = generateLabels(domain);
    const labels = parseLabels(generatedLabels, generatedLabels, false);
    expect(labels.data).toEqual(domain);
  });
  testProp('labels pointer post-label', [domainArb], (domain) => {
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
  testProp('labels pointer pre-label', [domainArb], (domain) => {
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
    [domainArb, domainArb],
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
  testProp('labels pointer recursion', [domainArb], (domain) => {
    const generatedLabels = generateLabels(domain, [0xc0, 0x00]);
    const parser = () => {
      parseLabels(generatedLabels, generatedLabels, true);
    };
    expect(parser).toThrow(ErrorDNSParse);
  });
  testProp('questions', [fc.array(questionRecordArb)], (questions) => {
    const generatedQuestions = generateQuestionRecords(questions);
    const parsedQuestions = parseQuestionRecords(
      generatedQuestions,
      generatedQuestions,
      questions.length,
    );
    expect(parsedQuestions.data).toEqual(questions);
  });
  testProp('packet flags', [packetFlagsArb], (flags) => {
    const encodedFlags = generatePacketFlags(flags);
    const decodedFlags = parsePacketFlags(encodedFlags);
    expect(decodedFlags.data).toEqual(flags);
  });
  testProp('resource records a', [fc.array(aRecordArb)], (resourceRecords) => {
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
    [fc.array(aaaaRecordArb)],
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
    [fc.array(cnamePtrRecordArb)],
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
    [fc.array(srvRecordArb)],
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
    [fc.array(txtRecordArb)],
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
  testProp('packet', [packetArb], (packet) => {
    const generatedPacket = generatePacket(packet as any);
    const parsedPacket = parsePacket(generatedPacket);
    expect(parsedPacket).toEqual(packet);
  });
});
