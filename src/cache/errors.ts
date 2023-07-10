import { AbstractError } from "@matrixai/errors";

class ErrorCache<T> extends AbstractError<T> {
  static description = 'Cache error';
}

class ErrorCacheDestroyed<T> extends ErrorCache<T> {
  static description = 'ResourceRecordCache is destroyed';
}

export {
  ErrorCache,
  ErrorCacheDestroyed,
}
