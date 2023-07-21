import type { Host } from '@/types';
import * as utils from '@/utils';

describe('utils', () => {
  test('detect IPv4 mapped IPv6 addresses', () => {
    expect(utils.isIPv4MappedIPv6('::ffff:127.0.0.1')).toBe(true);
    expect(utils.isIPv4MappedIPv6('::ffff:7f00:1')).toBe(true);
    expect(utils.isIPv4MappedIPv6('::')).toBe(false);
    expect(utils.isIPv4MappedIPv6('::1')).toBe(false);
    expect(utils.isIPv4MappedIPv6('127.0.0.1')).toBe(false);
    expect(utils.isIPv4MappedIPv6('::ffff:4a7d:2b63')).toBe(true);
    expect(utils.isIPv4MappedIPv6('::ffff:7f00:800')).toBe(true);
    expect(utils.isIPv4MappedIPv6('::ffff:255.255.255.255')).toBe(true);
  });
});
