import { fc, testProp } from '@fast-check/jest';
import {
  toResourceRecords,
  RClass,
  RType,
  encodeUInt32BE,
  fromName,
  encodeUInt16BE,
  fromIPv6,
  toIPv6,
} from '@/dns';

describe('ResourceRecord', () => {
  testProp(
    'Decode - A',
    [
      fc.record({
        name: fc.domain(),
        type: fc.constant(RType.A),
        flush: fc.boolean(),
        class: fc.constant(RClass.IN),
        ttl: fc.integer({ min: -2147483648, max: 2147483647 }), // 32-bit Signed Integer Limits
        data: fc.ipV4(),
      }),
    ],
    (originalRR) => {
      const rawRR: Uint8Array = new Uint8Array([
        ...fromName(originalRR.name),
        ...encodeUInt16BE(originalRR.type),
        ...encodeUInt16BE(
          originalRR.class | (originalRR.flush ? 0x8000 : 0x0000),
        ),
        ...encodeUInt32BE(originalRR.ttl), // TTL: 60 seconds
        0x00,
        0x04, // Data length: 4 bytes
        ...originalRR.data.split('.').map((s) => parseInt(s)),
      ]);
      const decodedRR = toResourceRecords(rawRR, 0, 1);

      expect(decodedRR).toEqual({
        data: [originalRR],
        readBytes: rawRR.byteLength,
      });
    },
  );

  testProp(
    'Decode - AAAA',
    [
      fc.record({
        name: fc.domain(),
        type: fc.constant(RType.AAAA),
        flush: fc.boolean(),
        class: fc.constant(RClass.IN),
        ttl: fc.integer({ min: -2147483648, max: 2147483647 }), // 32-bit Signed Integer Limits
        data: fc.ipV6().chain((ip) => fc.constant(toIPv6(fromIPv6(ip)))),
      }),
    ],
    (originalRR) => {
      const rawRR: Uint8Array = new Uint8Array([
        ...fromName(originalRR.name),
        ...encodeUInt16BE(originalRR.type),
        ...encodeUInt16BE(
          originalRR.class | (originalRR.flush ? 0x8000 : 0x0000),
        ),
        ...encodeUInt32BE(originalRR.ttl), // TTL: 60 seconds
        0x00,
        0x10, // Data length: 16 bytes
        ...fromIPv6(originalRR.data),
      ]);
      const decodedRR = toResourceRecords(rawRR, 0, 1);

      expect(decodedRR).toEqual({
        data: [originalRR],
        readBytes: rawRR.byteLength,
      });
    },
  );

  testProp(
    'Decode - CNAME, PTR',
    [
      fc.record({
        name: fc.domain(),
        type: fc.constantFrom(RType.CNAME, RType.PTR),
        flush: fc.boolean(),
        class: fc.constant(RClass.IN),
        ttl: fc.integer({ min: -2147483648, max: 2147483647 }), // 32-bit Signed Integer Limits
        data: fc.domain(),
      }),
    ],
    (originalRR) => {
      const encodedData = fromName(originalRR.data);
      const rawRR: Uint8Array = new Uint8Array([
        ...fromName(originalRR.name),
        ...encodeUInt16BE(originalRR.type),
        ...encodeUInt16BE(
          originalRR.class | (originalRR.flush ? 0x8000 : 0x0000),
        ),
        ...encodeUInt32BE(originalRR.ttl), // TTL: 60 seconds
        ...encodeUInt16BE(encodedData.byteLength), // Data length: 4 bytes
        ...encodedData,
      ]);
      const decodedRR = toResourceRecords(rawRR, 0, 1);

      expect(decodedRR).toEqual({
        data: [originalRR],
        readBytes: rawRR.byteLength,
      });
    },
  );
});
