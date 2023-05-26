import { toPacketFlags, fromPacketFlags, OpCode, PacketType, RCode } from "@/dns";
import { fc, testProp } from "@fast-check/jest";

const fc_opcodes = fc.constantFrom(...Object.keys(OpCode).filter(key => isNaN(Number(key))).map(c => OpCode[c]));
const fc_rcodes = fc.constantFrom(...Object.keys(RCode).filter(key => isNaN(Number(key))).map(c => RCode[c]));

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
      checkingDisabled: false
    });
  });
  testProp(
    "Full",
    [fc.record({
      type: fc.constantFrom(PacketType.QUERY, PacketType.RESPONSE),
      opcode: fc_opcodes,
      rcode: fc_rcodes,
      authoritativeAnswer: fc.boolean(),
      truncation: fc.boolean(),
      recursionDesired: fc.boolean(),
      recursionAvailable: fc.boolean(),
      zero: fc.boolean(),
      authenticData: fc.boolean(),
      checkingDisabled: fc.boolean()
    })],
    (originalFlags) => {
      const encodedFlags = fromPacketFlags(originalFlags);
      const decodedFlags = toPacketFlags(encodedFlags);

      expect(decodedFlags).toEqual(originalFlags);
    }
  )
});
