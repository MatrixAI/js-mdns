import { fc, testProp } from '@fast-check/jest';
import {
  parseResourceRecords,
  RClass,
  RType,
  encodeUInt32BE,
  generateLabels,
  encodeUInt16BE,
  generateIPv6,
  parseIPv6,
  concatUInt8Array,
  generateTXTRecordData,
  generateSRVRecordData,
  generateResourceRecord,
  StringRecord,
  parseResourceRecord,
} from '@/dns';

const FC_UINT32 = fc.integer({ min: 0, max: 4294967295 }); // 32-Bit Unsigned Integer Limits
const FC_UINT16 = fc.integer({ min: 0, max: 65535 }); // 16-Bit Unsigned Integer Limits

describe('ResourceRecord', () => {
  testProp(
    'parse a record',
    [
      fc.record({
        name: fc.domain(),
        type: fc.constant(RType.A),
        flush: fc.boolean(),
        class: fc.constant(RClass.IN),
        ttl: FC_UINT32, // 32-bit Signed Integer Limits
        data: fc.ipV4(),
      }),
    ],
    (originalRR) => {

      const generatedRR = generateResourceRecord(originalRR as StringRecord);
      const parsedRR = parseResourceRecord(generatedRR, generatedRR);

      expect(parsedRR.data).toEqual(originalRR);
      expect(parsedRR.remainder.length).toEqual(0);
    },
  );
  testProp(
    'parse a record',
    [
      fc.record({
        name: fc.domain(),
        type: fc.constant(RType.A),
        flush: fc.boolean(),
        class: fc.constant(RClass.IN),
        ttl: FC_UINT32, // 32-bit Signed Integer Limits
        data: fc.ipV4(),
      }),
    ],
    (originalRR) => {
      const rawRR: Uint8Array = concatUInt8Array(
        generateLabels(originalRR.name),
        encodeUInt16BE(originalRR.type),
        encodeUInt16BE(
          originalRR.class | (originalRR.flush ? 0x8000 : 0x0000),
        ),
        encodeUInt32BE(originalRR.ttl), // TTL: 60 seconds
        new Uint8Array(
          [0x00, 0x04] // Data length: 4 bytes
          .concat(originalRR.data.split('.').map((s) => parseInt(s)))
        ),
      );
      const decodedRR = parseResourceRecords(rawRR, rawRR, 1);

      expect(decodedRR.data).toEqual([originalRR]);
      expect(decodedRR.remainder.length).toEqual(0);
    },
  );

  testProp(
    'parse aaaa record',
    [
      fc.record({
        name: fc.domain(),
        type: fc.constant(RType.AAAA),
        flush: fc.boolean(),
        class: fc.constant(RClass.IN),
        ttl: FC_UINT32,
        data: fc.ipV6().chain((ip) => fc.constant(parseIPv6(generateIPv6("0:0:0:0:0:0:0:0")).data)),
      }),
    ],
    (originalRR) => {
      const rawRR: Uint8Array = concatUInt8Array(
        generateLabels(originalRR.name),
        encodeUInt16BE(originalRR.type),
        encodeUInt16BE(
          originalRR.class | (originalRR.flush ? 0x8000 : 0x0000),
        ),
        encodeUInt32BE(originalRR.ttl), // TTL: 60 seconds
        encodeUInt16BE(16), // Data length: 16 bytes
        generateIPv6(originalRR.data),
      );
      const decodedRR = parseResourceRecords(rawRR, rawRR, 1);

      expect(decodedRR.data).toEqual([originalRR]);
      expect(decodedRR.remainder.length).toEqual(0);
    },
  );

  testProp(
    'parse cname ptr record',
    [
      fc.record({
        name: fc.domain(),
        type: fc.constantFrom(RType.CNAME, RType.PTR),
        flush: fc.boolean(),
        class: fc.constant(RClass.IN),
        ttl: FC_UINT32,
        data: fc.domain(),
      }),
    ],
    (originalRR) => {
      const encodedData = generateLabels(originalRR.data);
      const rawRR: Uint8Array = concatUInt8Array(
        generateLabels(originalRR.name),
        encodeUInt16BE(originalRR.type),
        encodeUInt16BE(
          originalRR.class | (originalRR.flush ? 0x8000 : 0x0000),
        ),
        encodeUInt32BE(originalRR.ttl), // TTL: 60 seconds
        encodeUInt16BE(encodedData.byteLength), // Data length: 4 bytes
        encodedData,
      );
      const decodedRR = parseResourceRecords(rawRR, rawRR, 1);

      expect(decodedRR.data).toEqual([originalRR]);
      expect(decodedRR.remainder.length).toEqual(0);
    },
  );

  testProp(
    'parse txt record',
    [
      fc.record({
        name: fc.domain(),
        type: fc.constant(RType.TXT),
        flush: fc.boolean(),
        class: fc.constant(RClass.IN),
        ttl: FC_UINT32,
        data: fc.dictionary(fc.unicodeString(), fc.unicodeString()),
      }),
    ],
    (originalRR) => {
      const encodedData = generateTXTRecordData(originalRR.data);
      const rawRR: Uint8Array = concatUInt8Array(
        generateLabels(originalRR.name),
        encodeUInt16BE(originalRR.type),
        encodeUInt16BE(
          originalRR.class | (originalRR.flush ? 0x8000 : 0x0000),
        ),
        encodeUInt32BE(originalRR.ttl),

        encodeUInt16BE(encodedData.byteLength),
        encodedData
      );
      const decodedRR = parseResourceRecords(rawRR, rawRR, 1);

      expect(decodedRR.data).toEqual([originalRR]);
      expect(decodedRR.remainder.length).toEqual(0);
    },
  );

  testProp(
    'parse srv record',
    [
      fc.record({
        name: fc.domain(),
        type: fc.constant(RType.SRV),
        flush: fc.boolean(),
        class: fc.constant(RClass.IN),
        ttl: FC_UINT32,
        data: fc.record({
          priority: FC_UINT16,
          weight: FC_UINT16,
          port: FC_UINT16,
          target: fc.domain()
        })
      }),
    ],
    (originalRR) => {
      const encodedData = generateSRVRecordData(originalRR.data);
      const rawRR: Uint8Array = concatUInt8Array(
        generateLabels(originalRR.name),
        encodeUInt16BE(originalRR.type),
        encodeUInt16BE(
          originalRR.class | (originalRR.flush ? 0x8000 : 0x0000),
        ),
        encodeUInt32BE(originalRR.ttl),

        encodeUInt16BE(encodedData.byteLength),
        encodedData
      );
      const decodedRR = parseResourceRecords(rawRR, rawRR, 1);

      expect(decodedRR.data).toEqual([originalRR]);
      expect(decodedRR.remainder.length).toEqual(0);
    },
  );
});
