import { AbstractError } from '@matrixai/errors';

class ErrorMDNS<T> extends AbstractError<T> {
  static description = 'MDNS Error';
}

class ErrorMDNSRunning<T> extends ErrorMDNS<T> {
  static description = 'MDNS is running';
}

class ErrorMDNSNotRunning<T> extends ErrorMDNS<T> {
  static description = 'MDNS is not running';
}

class ErrorMDNSInvalidMulticastAddress<T> extends ErrorMDNS<T> {
  static description = 'MDNS cannot process the invalid multicast address';
}

class ErrorMDNSInterfaceRange<T> extends ErrorMDNS<T> {
  static description = 'MDNS interface range error';
}

class ErrorMDNSSocket<T> extends ErrorMDNS<T> {
  static description = 'MDNS socket error';
}

class ErrorMDNSSocketInvalidBindAddress<T> extends ErrorMDNSSocket<T> {
  static description = 'MDNS cannot bind to the specified address';
}

class ErrorMDNSSocketInvalidSendAddress<T> extends ErrorMDNSSocket<T> {
  static description = 'MDNS cannot send to the specified address';
}

export {
  ErrorMDNS,
  ErrorMDNSRunning,
  ErrorMDNSNotRunning,
  ErrorMDNSInterfaceRange,
  ErrorMDNSInvalidMulticastAddress,
  ErrorMDNSSocket,
  ErrorMDNSSocketInvalidBindAddress,
  ErrorMDNSSocketInvalidSendAddress,
};
