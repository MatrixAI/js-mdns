import { ResourceRecordHeaderId, ResourceRecordId, ResourceRecordIdEncoded, TaskId, TaskIdEncoded } from "./types";
import crypto from "crypto";
import { QuestionRecord, ResourceRecord } from "@/dns";

/**
 * Generates ResourceRecordId
 */
function createResourceRecordIdGenerator(): () => ResourceRecordId {
  return () => crypto.randomBytes(8).toString("hex") as ResourceRecordId;
}

/**
 * Converts `ResourceRecord` or `QuestionRecord` to `ResourceRecordHeaderId`
 */
function toRecordHeaderId(record: ResourceRecord | QuestionRecord): ResourceRecordHeaderId {
  return [record.name, record.type, record.class].join('\u0000') as ResourceRecordHeaderId;
}

/**
 * Converts `ResourceRecordHeaderId` to `QuestionRecord`
 */
function fromRecordHeaderId(key: ResourceRecordHeaderId): QuestionRecord {
  let name, type, qclass;
  [name, type, qclass] = key.split('\u0000');
  return {
    name,
    type: parseInt(type),
    class: parseInt(qclass),
    unicast: false,
  };
}

export {
  createResourceRecordIdGenerator,
  toRecordHeaderId,
  fromRecordHeaderId,
}

export * from './types';
