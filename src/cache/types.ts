import type { CachableResourceRecord } from '../dns/types.js';
import type { Hostname } from '../types.js';

type CachableResourceRecordRow = CachableResourceRecord & {
  timestamp: number;
  relatedHostname?: Hostname;
};

export type { CachableResourceRecordRow };
