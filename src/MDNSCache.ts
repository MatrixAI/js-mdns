import { Timer } from "@matrixai/timer"
import { QClass, QType, QuestionRecord, ResourceRecord, RType } from "./dns"
import { MDNSCacheExpiredEvent } from "./events";
import { Hostname } from "./types";

class MDNSCache extends EventTarget {
  protected cache: Map<string, { record: ResourceRecord, timer: Timer }> = new Map()

  public set(records: ResourceRecord | ResourceRecord[]) {
    if (!Array.isArray(records)) records = [records];
      for (const record of records) {
        const recordKey = MDNSCache.toRecordKey(record);
      const ttl: number = (record as any).ttl;
      const flush: boolean = (record as any).flush;

      const existingRecord = this.cache.get(recordKey);
      // If the record exists and is being flushed, delete it
      if (flush) {
        if (typeof existingRecord !== 'undefined') {
          this.remove(existingRecord.record);
          if (ttl === 0) continue;
        }
      }
      else if (typeof existingRecord !== 'undefined') return;
      this.cache.set(recordKey, { record, timer: new Timer(() => {
        this.dispatchEvent(new MDNSCacheExpiredEvent({detail: record}));
        this.cache.delete(recordKey);
      }, ttl * 1000 ) });
    }
  }

  public remove(records: (QuestionRecord | ResourceRecord) | (QuestionRecord | ResourceRecord)[]) {
    if (!Array.isArray(records)) records = [records];
    for (const record of records) {
      if ((record as any).class === QClass.ANY || (record as any).type === QType.ANY) {
        const foundRecords = [...this.cache.values()].filter(wrapper => (
          (record.name === wrapper.record.name) &&
          ((record as any).class === QClass.ANY || (wrapper.record as any).class === (record as any).class) &&
          (record.type === QType.ANY || (wrapper.record as any).type === record.type)
        ))
        for (const foundRecord of foundRecords) {
          foundRecord.timer.cancel();
        }
        continue;
      }
      const recordKey = MDNSCache.toRecordKey(record);
      this.cache.get(recordKey)?.timer.cancel();
      this.cache.delete(recordKey);
    }
  }

  public get(records: (QuestionRecord | ResourceRecord) | (QuestionRecord | ResourceRecord)[]): ResourceRecord[] {
    if (!Array.isArray(records)) records = [records];
    const resourceRecords: ResourceRecord[] = [];
    for (const record of records) {
      if ((record as any).class === QClass.ANY || (record as any).type === QType.ANY) {
        resourceRecords.push(...[...this.cache.values()].filter(wrapper => (
          (record.name === wrapper.record.name) &&
          ((record as any).class === QClass.ANY || (wrapper.record as any).class === (record as any).class) &&
          (record.type === QType.ANY || (wrapper.record as any).type === record.type)
        )).map(wrapper => wrapper.record));
        continue;
      }
      const recordKey = MDNSCache.toRecordKey(record);
      resourceRecords.push(...[this.cache.get(recordKey)?.record ?? []].flat());
    }
    return resourceRecords;
  }

  public reverseServiceFdqnFind(record: ResourceRecord): Hostname[] {
    const fdqns: Set<string> = new Set();
    if (record.type === RType.SRV || record.type === RType.TXT) {
      fdqns.add(record.name);
    } else if (
      record.type === RType.PTR &&
      record.name !== '_services._dns-sd._udp.local'
    ) {
      fdqns.add(record.data);
    } else if (record.type === RType.A || record.type === RType.AAAA) {
      const externalRecords = this.getAll();
      const srvRecords = externalRecords.filter(
        (externalRecord) =>
          externalRecord.type === RType.SRV &&
          externalRecord.data.target === record.name,
      );
      for (const srvRecord of srvRecords) {
        fdqns.add(srvRecord.name);
      }
    }
    return [...fdqns.values()] as Hostname[];
  }

  public getAll(): ResourceRecord[] {
    return [...this.cache.values()].map(wrapper => wrapper.record);
  }

  static toRecordKey(record: ResourceRecord | QuestionRecord): string {
    return [record.name, record.type, (record as any).class].join('\u0000');
  }

  static fromRecordKey(key: string): QuestionRecord {
    let name, type, qclass;
    [name, type, qclass] = key.split('\u0000');
    return {
      name,
      type: parseInt(type),
      class: parseInt(qclass),
      unicast: false,
    };
  }
}

export default MDNSCache;
