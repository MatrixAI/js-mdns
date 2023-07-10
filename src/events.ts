import type { Service } from './types';
import type { ResourceRecord } from './dns';

class MDNSServiceEvent extends Event {
  public detail: Service;
  constructor(
    options: EventInit & {
      detail: Service;
    },
  ) {
    super('service', options);
    this.detail = options.detail;
  }
}

class MDNSServiceRemovedEvent extends Event {
  public detail: Service;
  constructor(
    options: EventInit & {
      detail: Service;
    },
  ) {
    super('service-removed', options);
    this.detail = options.detail;
  }
}

export { MDNSServiceEvent, MDNSServiceRemovedEvent };
