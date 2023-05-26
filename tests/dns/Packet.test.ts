import { toPacket, OpCode, PacketType, RCode, QClass, QType, Packet } from "@/dns";

describe('Packet', () => {
  test('Packet Decode', () => {
    const rawPacket: Uint8Array = new Uint8Array([
      // Header
      0x00, 0x00, // ID
      0x84, 0x00, // Flags: Response, Authoritative Answer (AA)
      0x00, 0x01, // Question count
      0x00, 0x01, // Answer count
      0x00, 0x00, // Authority count
      0x00, 0x00, // Additional count

      // Question
      0x05, 0x5F, 0x68, 0x74, 0x74, 0x70, 0x04, 0x5F, 0x74, 0x63, 0x70, 0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x00, // _http._tcp.local
      0x00, 0x01, // Type: A
      0x00, 0x01, // Class: IN

      // Answer
      0xC0, 0x0C, // Name pointer to the question name
      0x00, 0x01, // Type: A
      0x00, 0x01, // Class: IN
      0x00, 0x00, 0x00, 0x3C, // TTL: 60 seconds
      0x00, 0x04, // Data length: 4 bytes
      0xC0, 0xA8, 0x00, 0x01, // IPv4 address: 192.168.0.1
    ]);

    const decodedPacket = toPacket(rawPacket);

    expect(decodedPacket).toEqual({
      id: 0,
      flags: {
        type: PacketType.RESPONSE,
        opcode: OpCode.QUERY,
        rcode: RCode.NoError,
        authoritativeAnswer: true,
        truncation: false,
        recursionDesired: false,
        recursionAvailable: false,
        zero: false,
        authenticData: false,
        checkingDisabled: false
      },
      questions: [{
        name: "_http._tcp.local",
        type: QType.A,
        class: QClass.IN
      }]
    } as Packet)
  });
});
