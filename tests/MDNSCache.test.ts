import { QClass, QType, RClass, ResourceRecord, RType } from "@/dns";
import MDNSCache from "@/MDNSCache";
import { fc, testProp } from "@fast-check/jest";
import { Timer } from "@matrixai/timer";

describe(MDNSCache.name, () => {
  testProp(
    'cache',
    [fc.domain()],
    (domain) => {
      const cache = new MDNSCache();
      const records: ResourceRecord[] = [
        {
          name: domain,
          type: RType.A,
          class: RClass.IN,
          flush: true,
          data: "",
          ttl: 0,
        },
        {
          name: domain,
          type: RType.AAAA,
          class: RClass.IN,
          flush: true,
          data: "",
          ttl: 0,
        },
      ];

      cache.set(records);
    }
  );
});
