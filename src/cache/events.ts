import type { ResourceRecord } from '@/dns';

class MDNSCacheExpiredEvent extends Event {
  public detail: ResourceRecord;
  constructor(
    options: EventInit & {
      detail: ResourceRecord;
    },
  ) {
    super('expired', options);
    this.detail = options.detail;
  }
}

export { MDNSCacheExpiredEvent };
