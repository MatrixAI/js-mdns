import { AbstractError } from '@matrixai/errors';

class ErrorDNSParse<T> extends AbstractError<T> {
  static description = 'ErrorDNSParse';
}

export {
  ErrorDNSParse,
}
