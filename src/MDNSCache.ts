import { Timer } from "@matrixai/timer";
import { QClass, QType, QuestionRecord, ResourceRecord } from "./dns";
import { createResourceRecordIdGenerator, ResourceRecordHeaderId, ResourceRecordId } from "./ids";

class MDNSCache {
  private resourceRecordIdGenerator: () => ResourceRecordId = createResourceRecordIdGenerator();
  private resourceRecordCache: Map<ResourceRecordId, ResourceRecord> = new Map();
  private resourceRecordCacheByHeaderId: Map<ResourceRecordHeaderId, ResourceRecordId[]> = new Map();
  /*
    * This is by timestamp + ttl. This is only sorted when the timer is reset!
    */
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


  private resourceRecordCacheTimerReset() {
    this.resourceRecordCacheTimer.cancel();
    this.resourceRecordCacheByTimestampInsertionSort();
    const fastestExpiringRecordId = this.resourceRecordCacheByTimestamp.at(0);
    if (typeof fastestExpiringRecordId !== 'undefined') {
      const record = this.resourceRecordCache.get(fastestExpiringRecordId);
      const timestamp = this.resourceRecordCacheTimestamps.get(fastestExpiringRecordId);
      if (typeof timestamp !== 'undefined' && typeof record !== 'undefined') {
        const delayMilis = ((record as any).ttl * 1000) + timestamp - new Date().getTime();
        this.resourceRecordCacheTimer = new Timer(async () => {
          // TODO: Requery missing packets
          // TODO: Delete Records and Parse
          this.delete(record);
          // const fastestExpiringRecord = record;
          // (fastestExpiringRecord as any).ttl = 0;
          // (fastestExpiringRecord as any).flush = true;
          // await this.processIncomingResourceRecords([fastestExpiringRecord]);
          this.resourceRecordCacheTimerReset();
        }, delayMilis < 0 ? 0 : delayMilis);
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

  resourceRecordCacheByTimestampInsertionSort() {
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
