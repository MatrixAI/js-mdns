import type { QuestionRecord, CachableResourceRecord } from '@/dns';
import type { CachableResourceRecordRow } from './types';
import type { Hostname } from '@/types';
import { CreateDestroy, ready } from '@matrixai/async-init/dist/CreateDestroy';
import { Timer } from '@matrixai/timer';
import Table from '@matrixai/table';
import canonicalize from 'canonicalize';
import { QClass, QType, RType } from '@/dns';
import { MDNSCacheExpiredEvent } from './events';
import * as utils from './utils';
import * as errors from './errors';

interface ResourceRecordCache extends CreateDestroy {}
@CreateDestroy()
class ResourceRecordCache extends EventTarget {
  private resourceRecordCache: Table<CachableResourceRecordRow> = new Table(
    ['name', 'type', 'class', 'data', 'ttl', 'relatedHostname', 'timestamp'],
    [
      [['name', 'type', 'class', 'data'], (...vs) => canonicalize(vs)], // For uniqueness
      ['name', 'type', 'class'], // For matching questions
      ['name', 'class'], // For matching questions with type ANY
      ['name', 'type'], // For matching questions with class ANY
      ['name'], // For matching questions with class and type ANY
      ['relatedHostname'], // For reverse matching records on their relatedHostname,
    ],
  );

  // This is sorted by timestamp + ttl in milliseconds in descending order. This is only sorted when the timer is reset!
  private resourceRecordCacheIndexesByExpiration: Array<number> = [];
  private resourceRecordCacheTimer: Timer = new Timer();

  // The max amount of records that can be stored.
  private _max: number;
  private _timerDisabled: boolean;

  @ready(new errors.ErrorCacheDestroyed())
  public get max(): number {
    return this._max;
  }

  @ready(new errors.ErrorCacheDestroyed())
  public get timerDisabled(): boolean {
    return this._timerDisabled;
  }

  @ready(new errors.ErrorCacheDestroyed())
  public get count(): number {
    return this.resourceRecordCache.count;
  }

  public static async createMDNSCache({
    max = 5000, // Each service is about 5 records, so this is about 1000 services
    timerDisabled = false,
  }: {
    max?: number;
    timerDisabled?: boolean;
  } = {}) {
    return new this({
      max,
      timerDisabled
    });
  }

  constructor({ max, timerDisabled }) {
    super();
    this._max = max;
    this._timerDisabled = timerDisabled;
  }

  public async destroy() {
    this.resourceRecordCacheTimer.cancel();
  }

  @ready(new errors.ErrorCacheDestroyed())
  public set(records: CachableResourceRecord | CachableResourceRecord[]): void {
    if (!Array.isArray(records)) {
      return this.set([records]);
    }
    const cacheIterator = this.resourceRecordCache[Symbol.iterator]();
    for (const record of records) {
      // Update existing records if they already exist with a new TTL
      const existingUniqueRowIndexes = this.resourceRecordCache.whereRows(
        ['name', 'type', 'class', 'data'],
        [record.name, record.type, record.class, record.data],
      );

      if (existingUniqueRowIndexes.length > 0) {
        for (const index of existingUniqueRowIndexes) {
          this.resourceRecordCache.updateRow(index, {
            ...record,
            timestamp: new Date().getTime(),
          });
        }
        continue;
      }

      // If the record is being inserted, and there will exist more records than the maximum allowed after insertion, the oldest record is removed.
      if (this.resourceRecordCache.count >= this._max) {
        // ?.at(0) is used in case this._max is < 0
        const overflowRowI: number | undefined = cacheIterator
          .next()
          .value?.at(0);
        if (overflowRowI != null) {
          this.resourceRecordCacheIndexesByExpiration.splice(
            this.resourceRecordCacheIndexesByExpiration.indexOf(overflowRowI),
            1,
          );
          this.resourceRecordCache.deleteRow(overflowRowI);
        }
      }

      let relatedHostname: Hostname | undefined;
      if (
        record.type === RType.PTR &&
        record.name !== '_services._dns-sd._udp.local'
      ) {
        relatedHostname = record.data as Hostname;
      } else if (record.type === RType.SRV) {
        relatedHostname = record.data.target as Hostname;
      }

      const rowI = this.resourceRecordCache.insertRow({
        ...record,
        relatedHostname,
        timestamp: new Date().getTime(),
      });

      this.resourceRecordCacheIndexesByExpiration.push(rowI);
    }
    this.resourceRecordCacheTimerReset();
  }

  @ready(new errors.ErrorCacheDestroyed())
  public delete(
    records:
      | (QuestionRecord | CachableResourceRecord)
      | (QuestionRecord | CachableResourceRecord)[],
  ) {
    if (!Array.isArray(records)) {
      return this.delete([records]);
    }

    let rescheduleTimer = true;

    for (const record of records) {
      const indexes = ['name'];
      const keys: Array<any> = [record.name];
      if (record.type !== QType.ANY) {
        indexes.push('type');
        keys.push(record.type);
      }
      if (record.class !== QClass.ANY) {
        indexes.push('class');
        keys.push(record.class);
      }
      const foundRowIs = this.resourceRecordCache.whereRows(indexes, keys);
      for (const foundRowI of foundRowIs) {
        this.resourceRecordCache.deleteRow(foundRowI);
        const expirationIndex =
          this.resourceRecordCacheIndexesByExpiration.indexOf(foundRowI);
        // If the deleted record was the next to expire, we can reschedule the timer.
        // Otherwise there is no need, as the current timer to delete the earliest expiring record is still valid.
        // This is some nice optimization that will save us some unnecessary sorting, but it will mean that the expiration array is sorted less.
        // To note also, deletion doesn't actually even need the array to be sorted. As deleting from a stable sorted array doesn't changed that the array is already sorted.
        // TODO: This optimization can be done later...
        if (expirationIndex === 0) {
          rescheduleTimer = true;
        }
        if (expirationIndex !== -1) {
          this.resourceRecordCacheIndexesByExpiration.splice(
            expirationIndex,
            1,
          );
        }
      }
    }

    if (!rescheduleTimer) return;

    this.resourceRecordCacheTimerReset();
  }

  @ready(new errors.ErrorCacheDestroyed())
  public get(
    records:
      | (QuestionRecord | CachableResourceRecord)
      | (QuestionRecord | CachableResourceRecord)[],
  ): CachableResourceRecord[] {
    if (!Array.isArray(records)) {
      return this.get([records]);
    }

    const resourceRecords: CachableResourceRecord[] = [];
    for (const record of records) {
      const indexes = ['name'];
      const keys: Array<any> = [record.name];
      if (record.type !== QType.ANY) {
        indexes.push('type');
        keys.push(record.type);
      }
      if (record.class !== QClass.ANY) {
        indexes.push('class');
        keys.push(record.class);
      }
      const foundRowIs = this.resourceRecordCache.whereRows(indexes, keys);
      for (const foundRowI of foundRowIs) {
        const foundResourceRecordRows =
          this.resourceRecordCache.getRow(foundRowI);
        if (foundResourceRecordRows) {
          resourceRecords.push(
            utils.fromCachableResourceRecordRow(foundResourceRecordRows),
          );
        }
      }
    }
    return resourceRecords;
  }

  @ready(new errors.ErrorCacheDestroyed())
  public getHostnameRelatedResourceRecords(
    hostname: Hostname,
  ): CachableResourceRecord[] {
    const foundRowIs = this.resourceRecordCache.whereRows(
      ['relatedHostname'],
      [hostname],
    );
    const foundResourceRecords = foundRowIs.flatMap((rI) => {
      const row = this.resourceRecordCache.getRow(rI);
      return row != null ? utils.fromCachableResourceRecordRow(row) : [];
    });
    return foundResourceRecords;
  }

  public has(record: QuestionRecord | CachableResourceRecord): boolean {
    const indexes = ['name'];
    const keys: Array<any> = [record.name];
    if (record.type !== QType.ANY) {
      indexes.push('type');
      keys.push(record.type);
    }
    if (record.class !== QClass.ANY) {
      indexes.push('class');
      keys.push(record.class);
    }
    return this.resourceRecordCache.whereRows(indexes, keys).length > 0;
  }

  @ready(new errors.ErrorCacheDestroyed())
  private resourceRecordCacheTimerReset() {
    if (this._timerDisabled) return;

    this.resourceRecordCacheTimer.cancel();

    // Latest expiration is always at the end of the array
    utils.insertionSort(this.resourceRecordCacheIndexesByExpiration, (a, b) => {
      const aEntry = this.resourceRecordCache.getRow(a);
      const bEntry = this.resourceRecordCache.getRow(b);
      return (
        (bEntry?.timestamp ?? 0) +
        (bEntry?.ttl ?? 0) * 1000 -
        ((aEntry?.timestamp ?? 0) + (aEntry?.ttl ?? 0) * 1000)
      );
    });
    const fastestExpiringRowI =
      this.resourceRecordCacheIndexesByExpiration.at(-1);
    if (fastestExpiringRowI == null) return;
    const record = this.resourceRecordCache.getRow(fastestExpiringRowI);
    if (record == null) return;
    // RFC 6762 8.4. TTL always has a 1 second floor
    const ttl = record.ttl !== 0 ? record.ttl : 1;
    const delayMilis = ttl * 1000 + record.timestamp - new Date().getTime();
    this.resourceRecordCacheTimer = new Timer(
      async () => {
        // TODO: Requery missing packets
        // TODO: Delete Records and Parse
        this.dispatchEvent(
          new MDNSCacheExpiredEvent({
            detail: utils.fromCachableResourceRecordRow(record),
          }),
        );
        this.resourceRecordCache.deleteRow(fastestExpiringRowI);
        // As the timer is always set to the last element, we can assume that the element we are working on is always the last
        this.resourceRecordCacheIndexesByExpiration.splice(-1, 1);
        this.resourceRecordCacheTimerReset();
      },
      delayMilis > 0 ? delayMilis : 0,
    );
  }
}

export default ResourceRecordCache;
