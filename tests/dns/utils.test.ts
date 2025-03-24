import { fc, test } from '@fast-check/jest';
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
} from './utils.js';
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
} from '#dns/index.js';

describe('dns packet parser/generator', () => {
  test.prop([domainArb])('labels', (domain) => {
    const generatedLabels = generateLabels(domain);
    const labels = parseLabels(generatedLabels, generatedLabels, false);
    expect(labels.data).toEqual(domain);
  });
  test.prop([domainArb])('labels pointer post-label', (domain) => {
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
  test.prop([domainArb])('labels pointer pre-label', (domain) => {
    const generatedLabelsDomain = generateLabels(domain);
    const generatedLabels = concatUInt8Array(
      new Uint8Array([0xc0, 0x02]),
      generatedLabelsDomain,
    );
    const labels = parseLabels(generatedLabels, generatedLabels, true);
    expect(labels.data).toEqual(domain);
  });
  test.prop([domainArb, domainArb])(
    'labels pointer terminated label',
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
  test.prop([domainArb])('labels pointer recursion', (domain) => {
    const generatedLabels = generateLabels(domain, [0xc0, 0x00]);
    const parser = () => {
      parseLabels(generatedLabels, generatedLabels, true);
    };
    expect(parser).toThrow(ErrorDNSParse);
  });
  test.prop([fc.array(questionRecordArb)])('questions', (questions) => {
    const generatedQuestions = generateQuestionRecords(questions);
    const parsedQuestions = parseQuestionRecords(
      generatedQuestions,
      generatedQuestions,
      questions.length,
    );
    expect(parsedQuestions.data).toEqual(questions);
  });
  test.prop([packetFlagsArb])('packet flags', (flags) => {
    const encodedFlags = generatePacketFlags(flags);
    const decodedFlags = parsePacketFlags(encodedFlags);
    expect(decodedFlags.data).toEqual(flags);
  });
  test.prop([fc.array(aRecordArb)])('resource records a', (resourceRecords) => {
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
  test.prop([fc.array(aaaaRecordArb)])(
    'resource records aaaa',
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
  test.prop([fc.array(cnamePtrRecordArb)])(
    'resource records cname ptr',
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
  test.prop([fc.array(srvRecordArb)])(
    'resource records srv',
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
  test.prop([fc.array(txtRecordArb)])(
    'resource records txt',
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
  test.prop([packetArb])('packet', (packet) => {
    const generatedPacket = generatePacket(packet as any);
    const parsedPacket = parsePacket(generatedPacket);
    expect(parsedPacket).toEqual(packet);
  });
});
