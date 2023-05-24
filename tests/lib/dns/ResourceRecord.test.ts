import { decodeResourceRecords, RClass, RType } from "@/lib/dns/ResourceRecord";

describe('ResourceRecord', () => {
  // test('Decode - A', () => {
  //   const rawRR: Uint8Array = new Uint8Array([
  //     // Answer
  //     0x05, 0x5F, 0x68, 0x74, 0x74, 0x70, 0x04, 0x5F, 0x74, 0x63, 0x70, 0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x00, // Name pointer to the question name
  //     0x00, 0x01, // Type: A
  //     0x00, 0x01, // Class: IN
  //     0x00, 0x00, 0x00, 0x3C, // TTL: 60 seconds
  //     0x00, 0x04, // Data length: 4 bytes
  //     0xC0, 0xA8, 0x00, 0x01, // IPv4 address: 192.168.0.1
  //   ]);

  //   const decodedRR = decodeResourceRecords(rawRR, 0, 1);

  //   console.log(decodedRR);
  // });

  test('Decode - AAAA', () => {
    const rawRR: Uint8Array = new Uint8Array([
      // Answer
      0x05, 0x5F, 0x68, 0x74, 0x74, 0x70, 0x04, 0x5F, 0x74, 0x63, 0x70, 0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x00, // Name pointer to the question name
      0x00, 0x1c, // Type: A
      0x00, 0x01, // Class: IN
      0x00, 0x00, 0x00, 0x3C, // TTL: 60 seconds
      // RDLENGTH (data length): 16 bytes
      0x00, 0x10,
      // RDATA: IPv6 address
      0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
      0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd
    ]);

    const decodedRR = decodeResourceRecords(rawRR, 0, 1);

    expect(decodedRR).toEqual({
      data: [
        {
          name: '_http._tcp.local',
          type: RType.AAAA,
          class: RClass.IN,
          flush: false,
          ttl: 60,
          data: 'fd12:3456:789a:bcde:ef01:2345:6789:abcd'
        }
      ],
      readBytes: rawRR.byteLength
    })
  });

  // test('Decode - PTR', () => {
  //   const rawRR: Uint8Array = new Uint8Array([
  //     // Answer
  //     0x05, 0x5F, 0x68, 0x74, 0x74, 0x70, 0x04, 0x5F, 0x74, 0x63, 0x70, 0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x00, // Name pointer to the question name
  //     // RR Type: PTR (12)
  //     0x00, 0x0c,
  //     // RR Class: IN (1)
  //     0x00, 0x01,
  //     // RR TTL (time to live): 120 seconds
  //     0x00, 0x00, 0x00, 0x78,
  //     // RDLENGTH (data length): 17 bytes
  //     0x00, 0x11,
  //     // RDATA: "example.local"
  //     0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00
  //   ]);

  //   const decodedRR = decodeResourceRecords(rawRR, 0, 1);

  //   console.log(decodedRR);
  // });
});
