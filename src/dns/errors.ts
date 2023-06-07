import { AbstractError } from '@matrixai/errors';

class ErrorDNS<T> extends AbstractError<T> {
  static description = 'DNS Packet error';
}

class ErrorDNSParse<T> extends ErrorDNS<T> {
  static description = 'DNS Packet parse error';
}

class ErrorDNSGenerate<T> extends ErrorDNS<T> {
  static description = 'DNS Packet generation error';
}

export { ErrorDNS, ErrorDNSParse, ErrorDNSGenerate };
