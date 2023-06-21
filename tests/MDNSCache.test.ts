import { CachableResourceRecord, QClass, QType, QuestionRecord, RClass, RType } from "@/dns";
import { MDNSCacheExpiredEvent } from "@/events";
import MDNSCache from "@/MDNSCache";

describe(MDNSCache.name, () => {
  let cache: MDNSCache;

  beforeEach(() => {
    cache = MDNSCache.createMDNSCache();
  });

  afterEach(async () => {
    await cache.destroy();
  });

  // test('single', async () => {
  //   const records: CachableResourceRecord[] = [
  //     {
  //       name: 'test.local',
  //       type: RType.A,
  //       class: RClass.IN,
  //       flush: false,
  //       data: '192.168.0.1',
  //       ttl: 120,
  //     },
  //   ];
  //   cache.set(records);
  //   expect(cache.get(records)).toEqual(records);
  // });

  // test('multiple', () => {
  //   const domain = "test.local";
  //   const records: CachableResourceRecord[] = [
  //     {
  //       name: domain,
  //       type: RType.A,
  //       class: RClass.IN,
  //       flush: false,
  //       data: '192.168.0.1',
  //       ttl: 120,
  //     },
  //     {
  //       name: domain,
  //       type: RType.A,
  //       class: RClass.IN,
  //       flush: false,
  //       data: '192.168.0.2',
  //       ttl: 120,
  //     }
  //   ];
  //   cache.set(records);
  //   expect(cache.get(records[0])).toEqual(records);
  // });

  // test('any', () => {
  //   const domain = "test.local";
  //   const records: CachableResourceRecord[] = [
  //     {
  //       name: domain,
  //       type: RType.A,
  //       class: RClass.IN,
  //       flush: false,
  //       data: '192.168.0.1',
  //       ttl: 120,
  //     },
  //     {
  //       name: domain,
  //       type: RType.AAAA,
  //       class: RClass.IN,
  //       flush: false,
  //       data: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
  //       ttl: 120,
  //     },
  //   ];
  //   cache.set(records);
  //   const question: QuestionRecord = {
  //     name: domain,
  //     class: QClass.ANY,
  //     type: QType.ANY,
  //     unicast: false
  //   }
  //   expect(cache.get(question)).toEqual(records);
  // });

  test('timer', async () => {
    const domain = "test.local";
    const records: CachableResourceRecord[] = [
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.2',
        ttl: 2,
      },
      {
        name: domain,
        type: RType.A,
        class: RClass.IN,
        flush: false,
        data: '192.168.0.1',
        ttl: 1,
      },


    ];
    cache.set(records);

    await new Promise((resolve, reject) => {
      cache.addEventListener('expired', (event: MDNSCacheExpiredEvent) => {
        // console.log(event.detail);
      })
    });
  });
});
