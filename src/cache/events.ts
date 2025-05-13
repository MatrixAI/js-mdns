import type { CachableResourceRecord } from '../dns/types.js';
import { AbstractEvent } from '@matrixai/events';

abstract class EventResourceRecordCache<T = null> extends AbstractEvent<T> {}

class EventResourceRecordCacheDestroy extends EventResourceRecordCache {}

class EventResourceRecordCacheDestroyed extends EventResourceRecordCache {}

class EventResourceRecordCacheExpired extends EventResourceRecordCache<CachableResourceRecord> {}

export {
  EventResourceRecordCache,
  EventResourceRecordCacheDestroy,
  EventResourceRecordCacheDestroyed,
  EventResourceRecordCacheExpired,
};
