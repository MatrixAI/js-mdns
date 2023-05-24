import { Question } from "dns-packet";
import { decodePacketFlags, PacketFlags } from "./PacketFlags";
import { readUInt16BE } from "./utils";

export type Packet = {
  id: number;
  flags: PacketFlags;
  questions: Question[];
}

export const decodePacket = (buffer: Uint8Array): Packet => {
  const id = readUInt16BE(buffer, 0);
  const flags = readUInt16BE(buffer, 2);
  const qdcount = readUInt16BE(buffer, 4);
  const ancount = readUInt16BE(buffer, 6);
  const nscount = readUInt16BE(buffer, 8);
  const arcount = readUInt16BE(buffer, 10);

  return {
    id,
    flags: decodePacketFlags(flags),
    questions: []
  };
}

export default Packet;

