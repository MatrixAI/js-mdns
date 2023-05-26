import { fc, testProp } from '@fast-check/jest';
import {
  toPacketFlags,
  fromPacketFlags,
  OpCode,
  PacketType,
  RCode,
} from '@/dns';

const FC_OPCODES = fc.constantFrom(OpCode.QUERY);
const FC_RCODES = fc.constantFrom(RCode.NoError);

describe('PacketFlags', () => {
  test('Flag Decode', () => {
    const flags = 0b0000001000000000;
    const decodedFlags = toPacketFlags(flags);
    expect(decodedFlags).toEqual({
      type: PacketType.QUERY,
      opcode: OpCode.QUERY,
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
      const encodedFlags = fromPacketFlags(originalFlags);
      const decodedFlags = toPacketFlags(encodedFlags);

      expect(decodedFlags).toEqual(originalFlags);
    },
  );
});
