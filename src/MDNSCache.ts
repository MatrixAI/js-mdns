import { CreateDestroy } from "@matrixai/async-init/dist/CreateDestroy";
import { Timer } from "@matrixai/timer";
import { QClass, QType, QuestionRecord, CachableResourceRecord, RType } from "./dns";
import { MDNSCacheExpiredEvent } from "./events";
import { createResourceRecordIdGenerator, ResourceRecordHeaderId, ResourceRecordId, toRecordHeaderId } from "./ids";
import { Hostname } from "./types";
import * as utils from './utils';

interface MDNSCache extends CreateDestroy {}
@CreateDestroy()
class MDNSCache extends EventTarget {
  private resourceRecordIdGenerator: () => ResourceRecordId = createResourceRecordIdGenerator();
  private resourceRecordCache: Map<ResourceRecordId, CachableResourceRecord> = new Map();
  private resourceRecordCacheByHeaderId: Map<ResourceRecordHeaderId, ResourceRecordId[]> = new Map();
  private resourceRecordCacheByHostname: Map<Hostname, ResourceRecordId[]> = new Map();
  // This is by timestamp + ttl. This is only sorted when the timer is reset!
  private resourceRecordCacheByExpiration: ResourceRecordId[] = [];
  private resourceRecordCacheTimestamps: Map<ResourceRecordId, number> = new Map()
  private resourceRecordCacheTimer: Timer = new Timer();


  public static createMDNSCache() {
    return new this();
  }
  public async destroy() {
    this.resourceRecordCacheTimer.cancel();
  }

  public set(records: CachableResourceRecord | CachableResourceRecord[]): void {
    if (!Array.isArray(records)) {
      return this.set([records]);
    }
    for (const record of records) {
      const resourceRecordId = this.resourceRecordIdGenerator();
      this.resourceRecordCache.set(resourceRecordId, record);
      this.resourceRecordCacheTimestamps.set(resourceRecordId, new Date().getTime());
      this.resourceRecordCacheByExpiration.push(resourceRecordId);

      let foundHostName: Hostname | undefined;
      if (record.type === RType.PTR && record.name !== '_services._dns-sd._udp.local') {
        foundHostName = record.data as Hostname;
      }
      else if (record.type === RType.SRV) {
        foundHostName = record.data.target as Hostname;
      }
      if (foundHostName != null) {
        let resourceRecordCacheByHostname = this.resourceRecordCacheByHostname.get(foundHostName);
        if (typeof resourceRecordCacheByHostname === "undefined") {
          resourceRecordCacheByHostname = [];
          this.resourceRecordCacheByHostname.set(foundHostName, resourceRecordCacheByHostname);
        }
        resourceRecordCacheByHostname.push(resourceRecordId);
      }

      const relevantHeaders: (QuestionRecord | CachableResourceRecord)[] = [
        record,
        {
          name: record.name,
          type: record.type as number as QType,
          class: QClass.ANY,
          unicast: false
        },
        {
          name: record.name,
          type: QType.ANY,
          class: record.class as number as QClass,
          unicast: false
        },
        {
          name: record.name,
          type: QType.ANY,
          class: QClass.ANY,
          unicast: false
        }
      ];

      for (const header of relevantHeaders) {
        const headerId = toRecordHeaderId(header);
        let array = this.resourceRecordCacheByHeaderId.get(headerId);
        if (!Array.isArray(array)) {
          array = [];
          this.resourceRecordCacheByHeaderId.set(headerId, array);
        }
        array.push(resourceRecordId);
      }
    }
    this.resourceRecordCacheTimerReset();
  }

  public delete(records: (QuestionRecord | CachableResourceRecord) | (QuestionRecord | CachableResourceRecord)[]) {
    if (!Array.isArray(records)) {
      return this.delete([records]);
    }
    const relevantHeaders = records.flatMap((record) => [
      record,
      {
        name: record.name,
        type: record.type as number as QType,
        class: QClass.ANY,
        unicast: false
      },
      {
        name: record.name,
        type: QType.ANY,
        class: record.class as QClass,
        unicast: false
      },
      {
        name: record.name,
        type: QType.ANY,
        class: QClass.ANY,
        unicast: false
      }
    ]);
    for (const headers of relevantHeaders) {
      const resourceRecordHeaderId = toRecordHeaderId(headers);
      const resourceRecordIds = this.resourceRecordCacheByHeaderId.get(resourceRecordHeaderId) ?? [];
      const deletedResourceRecordIds: ResourceRecordId[] = [];
      for (const resourceRecordId of resourceRecordIds) {

        // Delete from resourceRecordCacheByHostname
        const foundResourceRecord = this.resourceRecordCache.get(resourceRecordId);
        if (foundResourceRecord != null) {
          let foundHostName: Hostname | undefined;
          if (foundResourceRecord.type === RType.PTR && foundResourceRecord.name !== '_services._dns-sd._udp.local') {
            foundHostName = foundResourceRecord.data as Hostname;
          }
          else if (foundResourceRecord.type === RType.SRV) {
            foundHostName = foundResourceRecord.data.target as Hostname;
          }
          if (foundHostName != null) {
            const resourceRecordCacheByHostname = this.resourceRecordCacheByHostname.get(foundHostName) ?? [];
            resourceRecordCacheByHostname.splice(resourceRecordCacheByHostname.indexOf(resourceRecordId), 1);
            if (resourceRecordCacheByHostname.length === 0) {
              this.resourceRecordCacheByHostname.delete(foundHostName);
            }
          }
        }

        this.resourceRecordCache.delete(resourceRecordId);
        this.resourceRecordCacheTimestamps.delete(resourceRecordId);
        const resourceRecordCacheByHeaderId = this.resourceRecordCacheByHeaderId.get(resourceRecordHeaderId);
        resourceRecordCacheByHeaderId?.splice(resourceRecordCacheByHeaderId.indexOf(resourceRecordId), 1);
        this.resourceRecordCacheByExpiration.splice(this.resourceRecordCacheByExpiration.indexOf(resourceRecordId), 1);
        deletedResourceRecordIds.push(resourceRecordId);
      }
      for (const deletedResourceRecordId of deletedResourceRecordIds) {
        resourceRecordIds.splice(resourceRecordIds.indexOf(deletedResourceRecordId), 1);
      }
    }
    this.resourceRecordCacheTimerReset();
  }

  private deleteByResourceRecordId(resourceRecordIds: ResourceRecordId | ResourceRecordId[]) {
    if (!Array.isArray(resourceRecordIds)) {
      return this.deleteByResourceRecordId([resourceRecordIds]);
    }
    for (const resourceRecordId of resourceRecordIds) {
      const foundResourceRecord = this.resourceRecordCache.get(resourceRecordId);
      if (foundResourceRecord == null) continue;
      // Delete from resourceRecordCacheByHostname
      let foundHostName: Hostname | undefined;
      if (foundResourceRecord.type === RType.PTR && foundResourceRecord.name !== '_services._dns-sd._udp.local') {
        foundHostName = foundResourceRecord.data as Hostname;
      }
      else if (foundResourceRecord.type === RType.SRV) {
        foundHostName = foundResourceRecord.data.target as Hostname;
      }
      if (foundHostName != null) {
        const resourceRecordCacheByHostname = this.resourceRecordCacheByHostname.get(foundHostName) ?? [];
        resourceRecordCacheByHostname.splice(resourceRecordCacheByHostname.indexOf(resourceRecordId), 1);
        if (resourceRecordCacheByHostname.length === 0) {
          this.resourceRecordCacheByHostname.delete(foundHostName);
        }
      }

      // Delete from resourceRecordCacheByHeaderId
      const relevantHeaders = [
        foundResourceRecord,
        {
          name: foundResourceRecord.name,
          type: foundResourceRecord.type as number as QType,
          class: QClass.ANY,
          unicast: false
        },
        {
          name: foundResourceRecord.name,
          type: QType.ANY,
          class: foundResourceRecord.class as number as QClass,
          unicast: false
        },
        {
          name: foundResourceRecord.name,
          type: QType.ANY,
          class: QClass.ANY,
          unicast: false
        }
      ];

      for (const header of relevantHeaders) {
        const resourceRecordHeaderId = toRecordHeaderId(header);
        const resourceRecordCacheByHeaderId = this.resourceRecordCacheByHeaderId.get(resourceRecordHeaderId);
        resourceRecordCacheByHeaderId?.splice(resourceRecordCacheByHeaderId.indexOf(resourceRecordId), 1);
      }

      // Delete from resourceRecordCache
      this.resourceRecordCache.delete(resourceRecordId);
      this.resourceRecordCacheTimestamps.delete(resourceRecordId);
      this.resourceRecordCacheByExpiration.splice(this.resourceRecordCacheByExpiration.indexOf(resourceRecordId), 1);
    }
    this.resourceRecordCacheTimerReset();
  }

  public get(records: (QuestionRecord | CachableResourceRecord) | (QuestionRecord | CachableResourceRecord)[]): CachableResourceRecord[] {
    if (!Array.isArray(records)) {
      return this.get([records]);
    }

    const resourceRecords: CachableResourceRecord[] = [];
    for (const record of records) {
      const resourceRecordHeaderId = toRecordHeaderId(record);
      const resourceRecordIds = this.resourceRecordCacheByHeaderId.get(resourceRecordHeaderId) ?? [];
      for (const resourceRecordId of resourceRecordIds) {
        const resourceRecord = this.resourceRecordCache.get(resourceRecordId);
        if (resourceRecord != null) {
          resourceRecords.push(resourceRecord);
        }
      }
    }
    return resourceRecords;
  }

  public getHostnameRelatedResourceRecords(hostname: Hostname): CachableResourceRecord[] {
    const resourceRecordIds = this.resourceRecordCacheByHostname.get(hostname) ?? [];
    return resourceRecordIds.flatMap((resourceRecordId) => this.resourceRecordCache.get(resourceRecordId) ?? []);
  }

  public has(records: QuestionRecord | CachableResourceRecord): boolean {
    const resourceRecordHeaderId = toRecordHeaderId(records);
    return this.resourceRecordCacheByHeaderId.has(resourceRecordHeaderId);
  }

  private resourceRecordCacheTimerReset() {
    this.resourceRecordCacheTimer.cancel();
    utils.insertionSort(
      this.resourceRecordCacheByExpiration,
      (a, b) => ((this.resourceRecordCacheTimestamps.get(a) ?? 0) + (this.resourceRecordCache.get(a)?.ttl ?? 0) * 1000) -
      ((this.resourceRecordCacheTimestamps.get(b) ?? 0) + (this.resourceRecordCache.get(b)?.ttl ?? 0) * 1000)
    );
    const fastestExpiringRecordId = this.resourceRecordCacheByExpiration.at(0);
    if (fastestExpiringRecordId != null) {
      const record = this.resourceRecordCache.get(fastestExpiringRecordId);
      const timestamp = this.resourceRecordCacheTimestamps.get(fastestExpiringRecordId);
      if (timestamp != null && record != null) {
        // RFC 6762 8.4. TTL always has a 1 second floor
        const ttl = record.ttl !== 0 ? record.ttl : 1;
        const delayMilis = (ttl * 1000) + timestamp - new Date().getTime();
        this.resourceRecordCacheTimer = new Timer(async () => {
          // TODO: Requery missing packets
          // TODO: Delete Records and Parse
          this.dispatchEvent(new MDNSCacheExpiredEvent({ detail: record }));
          this.deleteByResourceRecordId(fastestExpiringRecordId);
        }, delayMilis > 0 ? delayMilis : 0);
      }
    }
  }
}

export default MDNSCache;
