import { decodePacketFlags, PacketFlags } from "./PacketFlags";
import { decodeQuestions, Question } from "./Question";
import { readUInt16BE } from "./utils";

export type Packet = {
  id: number;
  flags: PacketFlags;
  questions: Question[];
}

export const decodePacket = (buffer: Uint8Array): Packet => {
  const id = readUInt16BE(buffer, 0);
  const flags = readUInt16BE(buffer, 2);
  const qdcount = readUInt16BE(buffer, 4); // Question Count
  const ancount = readUInt16BE(buffer, 6); // Answer Count
  const nscount = readUInt16BE(buffer, 8); // Authority Count
  const arcount = readUInt16BE(buffer, 10); // Additional Count

  return {
    id,
    flags: decodePacketFlags(flags),
    questions: decodeQuestions(buffer, 12, qdcount).data,
  };
}

export default Packet;

