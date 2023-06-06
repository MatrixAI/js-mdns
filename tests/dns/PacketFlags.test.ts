import { fc, testProp } from '@fast-check/jest';
import {
  parsePacketFlags,
  generatePacketFlags,
  PacketOpCode,
  PacketType,
  RCode,
  encodeUInt16BE,
} from '@/dns';

const FC_OPCODES = fc.constantFrom(PacketOpCode.QUERY);
const FC_RCODES = fc.constantFrom(RCode.NoError);

describe('PacketFlags', () => {
  test('Flag Decode', () => {
    const flags = encodeUInt16BE(0b0000001000000000);
    const decodedFlags = parsePacketFlags(flags);
    expect(decodedFlags.data).toEqual({
      type: PacketType.QUERY,
      opcode: PacketOpCode.QUERY,
      rcode: RCode.NoError,
      authoritativeAnswer: false,
      truncation: true,
      recursionDesired: false,
      recursionAvailable: false,
      zero: false,
      authenticData: false,
      checkingDisabled: false,
    });
  });
  testProp(
    'Full',
    [
      fc.record({
        type: fc.constantFrom(PacketType.QUERY, PacketType.RESPONSE),
        opcode: FC_OPCODES,
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
    (originalFlags) => {
      const encodedFlags = generatePacketFlags(originalFlags);
      const decodedFlags = parsePacketFlags(encodedFlags);

      expect(decodedFlags.data).toEqual(originalFlags);
    },
  );
});
