import type { Service } from './types';
import type {
  ErrorMDNSPacketParse,
  ErrorMDNSSocketInternal,
  ErrorMDNSSocketInvalidReceiveAddress,
  ErrorMDNSSocketInvalidSendAddress,
  ErrorMDNSSocketSendFailed,
} from './errors';
import { AbstractEvent } from '@matrixai/events';

abstract class EventMDNS<T = null> extends AbstractEvent<T> {}

class EventMDNSStart extends EventMDNS {}

class EventMDNSStarted extends EventMDNS {}

class EventMDNSStop extends EventMDNS {}

class EventMDNSStopped extends EventMDNS {}

class EventMDNSService extends EventMDNS<Service> {}

class EventMDNSServiceRemoved extends EventMDNS<Service> {}

class EventMDNSError extends EventMDNS<
  | ErrorMDNSPacketParse<unknown>
  | ErrorMDNSSocketInternal<unknown>
  | ErrorMDNSSocketInvalidSendAddress<unknown>
  | ErrorMDNSSocketInvalidReceiveAddress<unknown>
  | ErrorMDNSSocketSendFailed<unknown>
> {}

export {
  EventMDNS,
  EventMDNSStart,
  EventMDNSStarted,
  EventMDNSStop,
  EventMDNSStopped,
  EventMDNSService,
  EventMDNSServiceRemoved,
  EventMDNSError,
};
