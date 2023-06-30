import { Opaque } from "@/types";

type TaskId = Opaque<'TaskId', string>;
type TaskIdString = Opaque<'TaskIdEncoded', string>;
type TaskIdEncoded = Opaque<'TaskIdEncoded', string>;
type TaskHandlerId = Opaque<'TaskHandlerId', string>;

type ResourceRecordId = Opaque<'ResourceRecordId', string>;
type ResourceRecordIdString = Opaque<'ResourceRecordIdString', string>;
type ResourceRecordIdEncoded = Opaque<'ResourceRecordIdEncoded', string>;
type ResourceRecordHeaderId = Opaque<'ResourceRecordHeaderId', string>;

export {
  TaskId,
  TaskIdString,
  TaskIdEncoded,
  TaskHandlerId,
  ResourceRecordId,
  ResourceRecordIdString,
  ResourceRecordIdEncoded,
  ResourceRecordHeaderId
}
