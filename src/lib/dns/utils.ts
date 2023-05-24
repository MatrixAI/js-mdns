import { DecodedData } from "./types";

export const readUInt16BE = (data: Uint8Array, offset: number = 0): number => {
  return (data[offset] << 8) | data[offset + 1];
}

export const readUInt32BE = (data: Uint8Array, offset: number = 0): number => {
  return (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
}

export const encodeUInt16BE = (value: number): Uint8Array => {
  return new Uint8Array([(value >> 8) & 0xFF, value & 0xFF]);
}

export const encodeUInt32BE = (value: number): Uint8Array => {
  return new Uint8Array([(value >> 24) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF]);
}

// remember, the whole packet needs to be fed into this function, as the pointer is relative to the start of the packet.
export const decodeName = (data: Uint8Array, offset: number = 0): DecodedData<string> => {
  let currentIndex = offset;
  let name = '';
  let readBytes = 0;
  let foundPointer = false;

  while (data[currentIndex] !== 0) {
    if ((data[currentIndex] & 0xC0) === 0xC0) {
      const pointerOffset = readUInt16BE(data, currentIndex) & 0x3FFF;
      currentIndex = pointerOffset;
      readBytes += 2; // Compression pointer occupies 2 bytes
      foundPointer = true;
    } else {
      const labelLength = data[currentIndex];
      const label = new TextDecoder().decode(data.subarray(currentIndex + 1, currentIndex + 1 + labelLength));
      name += label + '.';
      currentIndex += labelLength + 1;
      if (!foundPointer) readBytes += labelLength + 1; // Label length + label characters occupy labelLength + 1 bytes
    }
  }

  if (!foundPointer) readBytes += 1; // Include the terminating null byte

  return { data: name.slice(0, -1), readBytes };
};

export const encodeName = (name: string): Uint8Array => {
  const labels = name.split('.');
  const encodedName: number[] = [];

  for (const label of labels) {
    if (label.length > 63) {
      throw new Error(`Label "${label}" exceeds the maximum length of 63 characters.`);
    }

    encodedName.push(label.length);

    for (let i = 0; i < label.length; i++) {
      const codePoint = label.codePointAt(i);
      if (codePoint === undefined) {
        throw new Error(`Failed to retrieve code point for label "${label}".`);
      }

      if (codePoint > 127) {
        // Code point requires UTF-8 encoding
        const encodedBytes = Array.from(new TextEncoder().encode(label.charAt(i)));
        encodedName.push(...encodedBytes);
      } else {
        // ASCII character, no encoding needed
        encodedName.push(codePoint);
      }
    }
  }

  encodedName.push(0); // Terminating null byte

  return new Uint8Array(encodedName);
}

export const decodeIPv6 = (buffer: Uint8Array, offset: number = 0): string => {
  const parts: string[] = [];

  for (let i = offset; i < offset + 16; i += 2) {
    const value = readUInt16BE(buffer, i).toString(16);
    parts.push(value);
  }

  return parts.join(':');
}

export const encodeIPv6 = (ip: string): Uint8Array => {
  const parts = ip.split(':');

  const buffer = new Uint8Array(16);

  let offset = 0;
  for (const part of parts) {
    const hexPart = parseInt(part, 16);

    buffer[offset++] = hexPart >> 8;
    buffer[offset++] = hexPart & 0xFF;
  }

  return buffer;
}
