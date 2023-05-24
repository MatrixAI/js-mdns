import { DecodedData } from "./types";
import { decodeName, readUInt16BE, readUInt16LE } from "./utils";

export type Question = {
  name: string;
  type: QType;
  class: QClass;
}

export const decodeQuestions = (buffer: Uint8Array, offset: number = 0, questionCount: number): DecodedData<Question[]> => {
  let totalReadBytes = 0;
  const questions: Question[] = [];
  while (totalReadBytes < buffer.byteLength || questions.length !== questionCount) {
    const totalReadBytesOffset = offset + totalReadBytes;
    const { data: name, readBytes } = decodeName(buffer, totalReadBytesOffset);
    questions.push({
      name,
      type: readUInt16BE(buffer, totalReadBytesOffset + readBytes),
      class: readUInt16BE(buffer, totalReadBytesOffset + readBytes + 2),
    });
    totalReadBytes += readBytes + 4;
  }
  return {
    data: questions,
    readBytes: totalReadBytes,
  }
}

export enum QClass { // RFC 1035 3.2.4. 3.2.5.
  IN = 1, // the internet
  ANY = 255,
  // incomplete list
}

export enum QType { // RFC 1035 3.2.2. 3.2.3.
  A = 1,
  CNAME = 5,
  PTR = 12,
  TXT = 16,
  AAAA = 28, // RFC 3596 2.1.
  SRV = 33, // RFC 2782
  OPT = 41, // RFC 6891
  NSEC = 47, // RFC 4034 4.
  ANY = 255,
  // incomplete list
}

