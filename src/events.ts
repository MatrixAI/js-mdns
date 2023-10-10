import type { Service } from './types';
import { AbstractEvent } from '@matrixai/events';

abstract class EventMDNS<T = null> extends AbstractEvent<T> {}

class EventMDNSStart extends EventMDNS {}

class EventMDNSStarted extends EventMDNS {}

class EventMDNSStop extends EventMDNS {}

class EventMDNSStopped extends EventMDNS {}

class EventMDNSService extends EventMDNS<Service> {}

class EventMDNSServiceRemoved extends EventMDNS<Service> {}

export {
  EventMDNS,
  EventMDNSStart,
  EventMDNSStarted,
  EventMDNSStop,
  EventMDNSStopped,
  EventMDNSService,
  EventMDNSServiceRemoved,
};
