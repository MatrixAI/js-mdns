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

class ErrorMDNSDestroyed<T> extends ErrorMDNS<T> {
  static description = 'MDNS is destroyed';
}

class ErrorMDNSSocket<T> extends ErrorMDNS<T> {
  static description = 'MDNS socket error';
}

class ErrorMDNSInvalidBindAddress<T> extends ErrorMDNSSocket<T> {
  static description = 'MDNS cannot bind to the specified address';
}

class ErrorMDNSInvalidSendAddress<T> extends ErrorMDNSSocket<T> {
  static description = 'MDNS cannot send to the specified address';
}

export {
  ErrorMDNS,
  ErrorMDNSRunning,
  ErrorMDNSNotRunning,
  ErrorMDNSDestroyed,
  ErrorMDNSSocket,
  ErrorMDNSInvalidBindAddress,
  ErrorMDNSInvalidSendAddress,
};
