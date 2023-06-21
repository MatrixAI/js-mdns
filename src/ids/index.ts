import { IdInternal, IdRandom, IdSortable } from "@matrixai/id";
import { ResourceRecordHeaderId, ResourceRecordId, ResourceRecordIdEncoded, TaskId, TaskIdEncoded } from "./types";
import crypto from "crypto";
import { QuestionRecord, ResourceRecord } from "@/dns";

/**
 * Generates TaskId
 * TaskIds are lexicographically sortable 128 bit IDs
 * They are strictly monotonic and unique with respect to the `nodeId`
 * When the `NodeId` changes, make sure to regenerate this generator
 */
 function createTaskIdGenerator(lastTaskId?: TaskId) {
  const generator = new IdSortable<TaskId>({
    lastId: lastTaskId,
    randomSource: (size) => crypto.randomBytes(size),
  });
  return () => generator.get();
}

/**
 * Encodes the TaskId as a `base32hex` string
 */
function encodeTaskId(taskId: TaskId): TaskIdEncoded {
  return taskId.toMultibase('base32hex') as TaskIdEncoded;
}

/**
 * Decodes an encoded TaskId string into a TaskId
 */
function decodeTaskId(taskIdEncoded: unknown): TaskId | undefined {
  if (typeof taskIdEncoded !== 'string') {
    return;
  }
  const taskId = IdInternal.fromMultibase<TaskId>(taskIdEncoded);
  if (taskId == null) {
    return;
  }
  // All TaskIds are 16 bytes long
  if (taskId.length !== 16) {
    return;
  }
  return taskId;
}


/**
 * Generates ResourceRecordId
 */
 function createResourceRecordIdGenerator(): () => ResourceRecordId {
  const generator = new IdRandom<ResourceRecordId>({
    randomSource: (size) => crypto.randomBytes(size),
  });
  return () => generator.get();
}


/**
 * Decodes an encoded ResourceRecordId string into a ResourceRecordId
 */
 function decodeResourceRecordId(resourceRecordIdEncoded: unknown): ResourceRecordId | undefined {
  if (typeof resourceRecordIdEncoded !== 'string') {
    return;
  }
  const resourceRecordId = IdInternal.fromMultibase<ResourceRecordId>(resourceRecordIdEncoded);
  if (resourceRecordId == null) {
    return;
  }
  // All NodeIds are 32 bytes long
  // The NodeGraph requires a fixed size for Node Ids
  if (resourceRecordId.length !== 32) {
    return;
  }
  return resourceRecordId;
}

/**
 * Encodes `ResourceRecordId` to `ResourceRecordIdEncoded`
 */
function encodeResourceRecordId(certId: ResourceRecordId): ResourceRecordIdEncoded {
  return certId.toBuffer().toString('hex') as ResourceRecordIdEncoded;
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
  createTaskIdGenerator,
  encodeTaskId,
  decodeTaskId,
  encodeResourceRecordId,
  decodeResourceRecordId,
  createResourceRecordIdGenerator,
  toRecordHeaderId,
  fromRecordHeaderId,
}

export * from './types';
