import { Timer } from "@matrixai/timer";
import { QClass, QType, QuestionRecord, ResourceRecord, RType } from "./dns";
import { MDNSCacheExpiredEvent } from "./events";
import { createResourceRecordIdGenerator, ResourceRecordHeaderId, ResourceRecordId } from "./ids";
import { Hostname } from "./types";

class MDNSCache extends EventTarget {
  private resourceRecordIdGenerator: () => ResourceRecordId = createResourceRecordIdGenerator();
  private resourceRecordCache: Map<ResourceRecordId, ResourceRecord> = new Map();
  private resourceRecordCacheByHeaderId: Map<ResourceRecordHeaderId, ResourceRecordId[]> = new Map();
  private resourceRecordCacheByHostname: Map<Hostname, ResourceRecordId[]> = new Map();
  // This is by timestamp + ttl. This is only sorted when the timer is reset!
  private resourceRecordCacheByTimestamp: ResourceRecordId[] = [];
  private resourceRecordCacheTimestamps: Map<ResourceRecordId, number> = new Map()
  private resourceRecordCacheTimer: Timer = new Timer();

  public set(records: ResourceRecord | ResourceRecord[]): void {
    if (!Array.isArray(records)) {
      return this.set([records]);
    }
    for (const record of records) {
      const resourceRecordId = this.resourceRecordIdGenerator();
      this.resourceRecordCache.set(resourceRecordId, record);
      this.resourceRecordCacheTimestamps.set(resourceRecordId, new Date().getTime());
      this.resourceRecordCacheByTimestamp.push(resourceRecordId);

      let foundHostName: Hostname | undefined;
      if (record.type === RType.PTR && record.name !== '_services._dns-sd._udp.local') {
        foundHostName = record.data as Hostname;
      }
      else if (record.type === RType.SRV) {
        foundHostName = record.data.target as Hostname;
      }
      if (typeof foundHostName !== "undefined") {
        let resourceRecordCacheByHostname = this.resourceRecordCacheByHostname.get(foundHostName);
        if (typeof resourceRecordCacheByHostname === "undefined") {
          resourceRecordCacheByHostname = [];
          this.resourceRecordCacheByHostname.set(foundHostName, resourceRecordCacheByHostname);
        }
        resourceRecordCacheByHostname.push(resourceRecordId);
      }

      const relevantHeaders: (QuestionRecord | ResourceRecord)[] = [
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
          class: (record as any).class as QClass,
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
        let array = this.resourceRecordCacheByHeaderId.get(MDNSCache.toRecordHeaderId(header));
        if (typeof array === "undefined") {
          array = [];
          this.resourceRecordCacheByHeaderId.set(MDNSCache.toRecordHeaderId(record), array);
        }
        array.push(resourceRecordId);
      }
    }
    this.resourceRecordCacheTimerReset();
  }

  public delete(records: (QuestionRecord | ResourceRecord) | (QuestionRecord | ResourceRecord)[]) {
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
        class: (record as any).class as QClass,
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
      const resourceRecordHeaderId = MDNSCache.toRecordHeaderId(headers);
      const resourceRecordIds = this.resourceRecordCacheByHeaderId.get(resourceRecordHeaderId) ?? [];
      const deletedResourceRecordIds: ResourceRecordId[] = [];
      for (const resourceRecordId of resourceRecordIds) {

        // Delete from resourceRecordCacheByHostname
        const foundResourceRecord = this.resourceRecordCache.get(resourceRecordId);
        if (typeof foundResourceRecord !== "undefined") {
          let foundHostName: Hostname | undefined;
          if (foundResourceRecord.type === RType.PTR && foundResourceRecord.name !== '_services._dns-sd._udp.local') {
            foundHostName = foundResourceRecord.data as Hostname;
          }
          else if (foundResourceRecord.type === RType.SRV) {
            foundHostName = foundResourceRecord.data.target as Hostname;
          }
          if (typeof foundHostName !== "undefined") {
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
        this.resourceRecordCacheByTimestamp.splice(this.resourceRecordCacheByTimestamp.indexOf(resourceRecordId), 1);
        deletedResourceRecordIds.push(resourceRecordId);
      }
      for (const deletedResourceRecordId of deletedResourceRecordIds) {
        resourceRecordIds.splice(resourceRecordIds.indexOf(deletedResourceRecordId), 1);
      }
    }
    this.resourceRecordCacheTimerReset();
  }

  public get(records: (QuestionRecord | ResourceRecord) | (QuestionRecord | ResourceRecord)[]): ResourceRecord[] {
    if (!Array.isArray(records)) {
      return this.get([records]);
    }
    const resourceRecords: ResourceRecord[] = [];
    for (const record of records) {
      const resourceRecordHeaderId = MDNSCache.toRecordHeaderId(record);
      const resourceRecordIds = this.resourceRecordCacheByHeaderId.get(resourceRecordHeaderId) ?? [];
      for (const resourceRecordId of resourceRecordIds) {
        const resourceRecord = this.resourceRecordCache.get(resourceRecordId);
        if (typeof resourceRecord !== "undefined") {
          resourceRecords.push(resourceRecord);
        }
      }
    }
    return resourceRecords;
  }

  public getHostnameRelatedResourceRecords(hostname: Hostname): ResourceRecord[] {
    const resourceRecordIds = this.resourceRecordCacheByHostname.get(hostname) ?? [];
    return resourceRecordIds.flatMap((resourceRecordId) => this.resourceRecordCache.get(resourceRecordId) ?? []);
  }

  public has(records: QuestionRecord | ResourceRecord): boolean {
    const resourceRecordHeaderId = MDNSCache.toRecordHeaderId(records);
    return this.resourceRecordCacheByHeaderId.has(resourceRecordHeaderId);
  }

  private resourceRecordCacheTimerReset() {
    this.resourceRecordCacheTimer.cancel();
    this.resourceRecordCacheByTimestampInsertionSort();
    const fastestExpiringRecordId = this.resourceRecordCacheByTimestamp.at(0);
    if (typeof fastestExpiringRecordId !== 'undefined') {
      const record = this.resourceRecordCache.get(fastestExpiringRecordId);
      const timestamp = this.resourceRecordCacheTimestamps.get(fastestExpiringRecordId);
      if (typeof timestamp !== 'undefined' && typeof record !== 'undefined') {
        // RFC 6762 8.4. TTL always has a 1 second floor
        const ttl = (record as any).ttl !== 0 ? (record as any).ttl : 1;
        const delayMilis = (ttl * 1000) + timestamp - new Date().getTime();
        this.resourceRecordCacheTimer = new Timer(async () => {
          // TODO: Requery missing packets
          // TODO: Delete Records and Parse
          this.delete(record);
          this.dispatchEvent(new MDNSCacheExpiredEvent({ detail: record }));
          this.resourceRecordCacheTimerReset();
        }, delayMilis > 0 ? delayMilis : 0);
      }
    }
  }

  static toRecordHeaderId(record: ResourceRecord | QuestionRecord): ResourceRecordHeaderId {
    return [record.name, record.type, (record as any).class].join('\u0000') as ResourceRecordHeaderId;
  }
  static fromRecordHeaderId(key: ResourceRecordHeaderId): QuestionRecord {
    let name, type, qclass;
    [name, type, qclass] = key.split('\u0000');
    return {
      name,
      type: parseInt(type),
      class: parseInt(qclass),
      unicast: false,
    };
  }

  private resourceRecordCacheByTimestampInsertionSort() {
    for (let i = 1; i < this.resourceRecordCacheByTimestamp.length; i++) {
      let currentId = this.resourceRecordCacheByTimestamp[i];
      let currentElement = this.resourceRecordCacheTimestamps.get(currentId);
      if (typeof currentElement === 'undefined') {
        continue;
      }
      let lastIndex = i - 1;
      let lastIndexElement = this.resourceRecordCacheTimestamps.get(this.resourceRecordCacheByTimestamp[lastIndex]);
      if (typeof lastIndexElement === 'undefined') {
        continue;
      }

      while (lastIndex >= 0 && lastIndexElement > currentElement) {
        this.resourceRecordCacheByTimestamp[lastIndex + 1] = this.resourceRecordCacheByTimestamp[lastIndex];
        lastIndex--;
        lastIndexElement = this.resourceRecordCacheTimestamps.get(this.resourceRecordCacheByTimestamp[lastIndex]);
        if (typeof lastIndexElement === 'undefined') {
          break;
        }
      }
      this.resourceRecordCacheByTimestamp[lastIndex + 1] = currentId;
    }
  }
}

export default MDNSCache;
