import type { CachableResourceRecord, QuestionRecord } from '@/dns';
import type { MDNSCacheExpiredEvent } from '@/events';
import { QClass, QType, RClass, RType } from '@/dns';
import { ResourceRecordCache } from '@/cache';

describe(ResourceRecordCache.name, () => {
  let cache: ResourceRecordCache;

  beforeEach(() => {
    cache = ResourceRecordCache.createMDNSCache();
  });

  afterEach(async () => {
    await cache.destroy();
  });

  test('single', async () => {
    const records: CachableResourceRecord[] = [
      {
        name: 'test.local',
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.1',
        ttl: 120,
      },
    ];
    cache.set(records);
    expect(cache.get(records)).toEqual(records);
  });

  test('multiple', () => {
    const domain = 'test.local';
    const records: CachableResourceRecord[] = [
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.1',
        ttl: 120,
      },
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.2',
        ttl: 120,
      },
    ];
    cache.set(records);
    expect(cache.get(records[0])).toEqual(records);
  });

  test('any', () => {
    const domain = 'test.local';
    const records: CachableResourceRecord[] = [
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.1',
        ttl: 120,
      },
      {
        name: domain,
        type: RType.AAAA,
        class: RClass.IN,
        flush: false,
        data: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        ttl: 120,
      },
    ];
    cache.set(records);
    const question: QuestionRecord = {
      name: domain,
      class: QClass.ANY,
      type: QType.ANY,
      unicast: false,
    };
    expect(cache.get(question)).toEqual(records);
  });

  test('expiry', async () => {
    const domain = 'test.local';
    const records: CachableResourceRecord[] = [
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.2',
        ttl: 3,
      },
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.1',
        ttl: 1,
      },
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.3',
        ttl: 1,
      },
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.4',
        ttl: 2,
      },
    ];
    cache.set(records);

    // The timer will have to be mocked in future, as waiting for the promise to resolve is time consuming
    await new Promise((resolve, reject) => {
      let expiredIndex = 0;
      const sortedRecords = records.sort((a, b) => a.ttl - b.ttl);
      cache.addEventListener('expired', (event: MDNSCacheExpiredEvent) => {
        try {
          expect(event.detail.ttl).toEqual(sortedRecords[expiredIndex].ttl);
        }
        catch (e) {
          reject(e);
        }
        if (expiredIndex === sortedRecords.length - 1) {
          resolve(null);
        }
        expiredIndex++;
      });
    });
  });
});
