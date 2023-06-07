import type { Packet } from '@/dns';
import { RClass, RType } from '@/dns';
import {
  parsePacket,
  PacketOpCode,
  PacketType,
  RCode,
  QClass,
  QType,
} from '@/dns';

describe('Packet', () => {
  test('parse a', () => {
    const rawPacket: Uint8Array = new Uint8Array([
      // Header
      0x00,
      0x00, // ID
      0x84,
      0x00, // Flags: Response, Authoritative Answer (AA)
      0x00,
      0x01, // Question count
      0x00,
      0x01, // Answer count
      0x00,
      0x00, // Authority count
      0x00,
      0x00, // Additional count

      // Question
      0x05,
      0x5f,
      0x68,
      0x74,
      0x74,
      0x70,
      0x04,
      0x5f,
      0x74,
      0x63,
      0x70,
      0x05,
      0x6c,
      0x6f,
      0x63,
      0x61,
      0x6c,
      0x00, // _http._tcp.local
      0x00,
      0x01, // Type: A
      0x00,
      0x01, // Class: IN

      // Answer
      0xc0,
      0x0c, // Name pointer to the question name
      0x00,
      0x01, // Type: A
      0x00,
      0x01, // Class: IN
      0x00,
      0x00,
      0x00,
      0x3c, // TTL: 60 seconds
      0x00,
      0x04, // Data length: 4 bytes
      0xc0,
      0xa8,
      0x00,
      0x01, // IPv4 address: 192.168.0.1
    ]);

    const decodedPacket = parsePacket(rawPacket);

    expect(decodedPacket).toEqual({
      id: 0,
      flags: {
        type: PacketType.RESPONSE,
        opcode: PacketOpCode.QUERY,
        rcode: RCode.NoError,
        authoritativeAnswer: true,
        truncation: false,
        recursionDesired: false,
        recursionAvailable: false,
        zero: false,
        authenticData: false,
        checkingDisabled: false,
      },
      questions: [
        {
          name: '_http._tcp.local',
          type: QType.A,
          class: QClass.IN,
          unicast: false,
        },
      ],
      additionals: [],
      answers: [
        {
          name: '_http._tcp.local',
          class: RClass.IN,
          type: RType.A,
          ttl: 60,
          flush: false,
          data: '192.168.0.1',
        },
      ],
      authorities: [],
    } as Packet);
  });
});
