import { Question } from "dns-packet";
import { decodePacketFlags, PacketFlags } from "./PacketFlags";
import { readUInt16BE } from "./utils";


export interface PacketOptions {
  id?: number;

  flags: PacketFlags;

  questions?: Question[];
  // answers?: ResourceRecord[];
  // authorities?: ResourceRecord[];
  // additionals?: ResourceRecord[];
}

class Packet {
  id;
  flags: PacketFlags;

  questions?: Question[];
  // answers?: undefined;
  // additionals?: undefined;
  // authorities?: undefined;

  constructor(options: PacketOptions) {
    this.id = options.id || 0;
    this.flags = options.flags;
    this.questions = options.questions;
  }

  public static decode(buffer: Uint8Array) {
    const id = readUInt16BE(buffer, 0);
    const flags = readUInt16BE(buffer, 2);
    const qdcount = readUInt16BE(buffer, 4);
    const ancount = readUInt16BE(buffer, 6);
    const nscount = readUInt16BE(buffer, 8);
    const arcount = readUInt16BE(buffer, 10);

    console.log(id)
    return new Packet({
      id,
      flags: decodePacketFlags(flags)
    });
  }
}

export default Packet;

