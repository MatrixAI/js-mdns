import { decodePacketFlags, OpCode, PacketType, RCode } from "@/lib/dns/PacketFlags";

describe('PacketFlags', () => {
  test('Flag Decode', () => {
    const flags = 0b0000001000000000;
    const decodedFlags = decodePacketFlags(flags);
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
});
