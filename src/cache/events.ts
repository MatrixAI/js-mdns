import type { CachableResourceRecord, ResourceRecord } from '@/dns';

class MDNSCacheExpiredEvent extends Event {
  public detail: CachableResourceRecord;
  constructor(
    options: EventInit & {
      detail: CachableResourceRecord;
    },
  ) {
    super('expired', options);
    this.detail = options.detail;
  }
}

export { MDNSCacheExpiredEvent };
