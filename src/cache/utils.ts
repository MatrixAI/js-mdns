import type { CachableResourceRecord } from '@/dns';
import type { CachableResourceRecordRow } from './types';
import type { Hostname } from '@/types';

function insertionSort<T>(arr: T[], compare: (a: T, b: T) => number) {
  for (let i = 1; i < arr.length; i++) {
    const temp = arr[i];
    let j = i - 1;
    while (j >= 0 && compare(arr[j], temp) > 0) {
      arr[j + 1] = arr[j];
      j--;
    }
    arr[j + 1] = temp;
  }
}

function toCachableResourceRecordRow(
  record: CachableResourceRecord,
  timestamp: number,
  relatedHostname?: Hostname,
): CachableResourceRecordRow {
  return {
    ...record,
    timestamp,
    relatedHostname,
  };
}

function fromCachableResourceRecordRow(
  row: CachableResourceRecordRow,
): CachableResourceRecord {
  return {
    name: row.name,
    type: row.type,
    class: row.class,
    ttl: row.ttl,
    flush: row.flush,
    data: row.data as any,
  };
}

export {
  insertionSort,
  toCachableResourceRecordRow,
  fromCachableResourceRecordRow,
};
