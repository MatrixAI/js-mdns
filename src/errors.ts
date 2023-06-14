import { AbstractError } from '@matrixai/errors';

class ErrorMDNS<T> extends AbstractError<T> {
  static description = 'MDNS Error';
}

class ErrorMDNSRunning<T> extends ErrorMDNS<T> {
  static description = 'MDNS is running';
}

class ErrorMDNSDestroyed<T> extends ErrorMDNS<T> {
  static description = 'MDNS is destroyed';
}

class ErrorMDNSInvalidBindAddress<T> extends ErrorMDNS<T> {
  static description = 'MDNS cannot bind to the specified address';
}

class ErrorMDNSInvalidSendAddress<T> extends ErrorMDNS<T> {
  static description = 'MDNS cannot send to the specified address';
}

export {
  ErrorMDNS,
  ErrorMDNSRunning,
  ErrorMDNSDestroyed,
  ErrorMDNSInvalidBindAddress,
  ErrorMDNSInvalidSendAddress,
};
