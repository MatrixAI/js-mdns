import type { CachableResourceRecord, QuestionRecord } from '@/dns';
import type { MDNSCacheExpiredEvent } from '@/cache/events';
import type { Host, Hostname } from '@/types';
import { fc, testProp } from '@fast-check/jest';
import { QClass, QType, RClass, RType } from '@/dns';
import { ResourceRecordCache } from '@/cache';
import { resourceRecordArb } from '../dns/utils';

const MAX_RECORDS = 100;

describe(ResourceRecordCache.name, () => {
  let cache: ResourceRecordCache;

  beforeEach(async () => {
    cache = await ResourceRecordCache.createResourceRecordCache({
      max: MAX_RECORDS,
    });
  });

  afterEach(async () => {
    await cache.destroy();
  });

  test('single', async () => {
    const records: CachableResourceRecord[] = [
      {
        name: 'test.local' as Hostname,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.1' as Host,
        ttl: 120,
      },
    ];
    cache.set(records);
    expect(cache.whereGet(records)).toEqual(records);
  });

  test('multiple', () => {
    const domain = 'test.local' as Hostname;
    const records: CachableResourceRecord[] = [
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.1' as Host,
        ttl: 120,
      },
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.2' as Host,
        ttl: 120,
      },
    ];
    cache.set(records);
    expect(cache.whereGet(records[0])).toEqual(records);
  });

  test('any', () => {
    const domain = 'test.local' as Hostname;
    const records: CachableResourceRecord[] = [
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.1' as Host,
        ttl: 120,
      },
      {
        name: domain,
        type: RType.AAAA,
        class: RClass.IN,
        flush: false,
        data: '2001:0db8:85a3:0000:0000:8a2e:0370:7334' as Host,
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
    expect(cache.whereGet(question)).toEqual(records);
  });

  testProp(
    'overflow',
    [
      fc.array(resourceRecordArb, {
        minLength: MAX_RECORDS + 1,
        maxLength: MAX_RECORDS + 1,
      }),
    ],
    (records) => {
      cache.set(records as CachableResourceRecord[]);
      expect(cache.count).toEqual(MAX_RECORDS);
      expect(
        cache.whereGet(records[0] as CachableResourceRecord).length,
      ).toEqual(0);
    },
  );

  test('expiry', async () => {
    const domain = 'test.local' as Hostname;
    const records: CachableResourceRecord[] = [
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.2' as Host,
        ttl: 3,
      },
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.1' as Host,
        ttl: 1,
      },
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.3' as Host,
        ttl: 1,
      },
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.4' as Host,
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
        } catch (e) {
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
