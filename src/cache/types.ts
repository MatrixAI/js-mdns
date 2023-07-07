import type { CachableResourceRecord } from '@/dns';

type CachableResourceRecordRow = CachableResourceRecord & {
  timestamp: number;
  relatedHostname?: string;
};

export type { CachableResourceRecordRow };
