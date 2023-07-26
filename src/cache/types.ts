import type { CachableResourceRecord } from '@/dns';
import type { Hostname } from '../types';

type CachableResourceRecordRow = CachableResourceRecord & {
  timestamp: number;
  relatedHostname?: Hostname;
};

export type { CachableResourceRecordRow };
