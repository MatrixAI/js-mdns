import type {
  Callback,
  Host,
  Hostname,
  NetworkInterfaces,
  PromiseDeconstructed,
  Service,
} from './types';
import type {
  StringRecord,
  ResourceRecord,
  QuestionRecord,
  QType,
  CachableResourceRecord,
} from '@/dns';
import dns from 'dns';
import os from 'os';
import { IPv4, IPv6, Validator } from 'ip-num';
import { RType, RClass, SRVRecord, TXTRecord, QClass } from '@/dns';

/**
 * Is it an IPv4 address?
 */
function isIPv4(host: string): host is Host {
  const [isIPv4] = Validator.isValidIPv4String(host);
  return isIPv4;
}

/**
 * Is it an IPv6 address?
 * This considers IPv4 mapped IPv6 addresses to also be IPv6 addresses.
 */
function isIPv6(host: string): host is Host {
  const [isIPv6] = Validator.isValidIPv6String(host);
  if (isIPv6) return true;
  // Test if the host is an IPv4 mapped IPv6 address.
  // In the future, `isValidIPv6String` should be able to handle this
  // and this code can be removed.
  return isIPv4MappedIPv6(host);
}

/**
 * There are 2 kinds of IPv4 mapped IPv6 addresses.
 * 1. ::ffff:127.0.0.1 - dotted decimal version
 * 2. ::ffff:7f00:1 - hex version
 * Both are accepted by Node's dgram module.
 */
function isIPv4MappedIPv6(host: string): host is Host {
  if (host.startsWith('::ffff:')) {
    try {
      // The `ip-num` package understands `::ffff:7f00:1`
      IPv6.fromString(host);
      return true;
    } catch {
      // But it does not understand `::ffff:127.0.0.1`
      const ipv4 = host.slice('::ffff:'.length);
      if (isIPv4(ipv4)) {
        return true;
      }
    }
  }
  return false;
}

function isIPv4MappedIPv6Hex(host: string): host is Host {
  if (host.startsWith('::ffff:')) {
    try {
      // The `ip-num` package understands `::ffff:7f00:1`
      IPv6.fromString(host);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

function isIPv4MappedIPv6Dec(host: string): host is Host {
  if (host.startsWith('::ffff:')) {
    // But it does not understand `::ffff:127.0.0.1`
    const ipv4 = host.slice('::ffff:'.length);
    if (isIPv4(ipv4)) {
      return true;
    }
  }
  return false;
}

/**
 * Takes an IPv4 address and returns the IPv4 mapped IPv6 address.
 * This produces the dotted decimal variant.
 */
function toIPv4MappedIPv6Dec(host: string): Host {
  if (!isIPv4(host)) {
    throw new TypeError('Invalid IPv4 address');
  }
  return ('::ffff:' + host) as Host;
}

/**
 * Takes an IPv4 address and returns the IPv4 mapped IPv6 address.
 * This produces the dotted Hexidecimal variant.
 */
function toIPv4MappedIPv6Hex(host: string): Host {
  if (!isIPv4(host)) {
    throw new TypeError('Invalid IPv4 address');
  }
  return IPv4.fromString(host).toIPv4MappedIPv6().toString() as Host;
}

/**
 * Extracts the IPv4 portion out of the IPv4 mapped IPv6 address.
 * Can handle both the dotted decimal and hex variants.
 * 1. ::ffff:7f00:1
 * 2. ::ffff:127.0.0.1
 * Always returns the dotted decimal variant.
 */
function fromIPv4MappedIPv6(host: string): Host {
  const ipv4 = host.slice('::ffff:'.length);
  if (isIPv4(ipv4)) {
    return ipv4 as Host;
  }
  const matches = ipv4.match(/^([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4})$/);
  if (matches == null) {
    throw new TypeError('Invalid IPv4 mapped IPv6 address');
  }
  const ipv4Hex = matches[1].padStart(4, '0') + matches[2].padStart(4, '0');
  const ipv4Hexes = ipv4Hex.match(/.{1,2}/g)!;
  const ipv4Decs = ipv4Hexes.map((h) => parseInt(h, 16));
  return ipv4Decs.join('.') as Host;
}

/**
 * This converts all `IPv4` formats to the `IPv4` decimal format.
 * `IPv4` decimal and `IPv6` hex formatted IPs are left unchanged.
 */
function toCanonicalIp(host: string) {
  if (isIPv4MappedIPv6(host)) {
    return fromIPv4MappedIPv6(host);
  }
  if (isIPv4(host) || isIPv6(host)) {
    return host;
  }
  throw new TypeError('Invalid IP address');
}

/**
 * This will resolve a hostname to the first host.
 * It could be an IPv6 address or IPv4 address.
 * This uses the OS's DNS resolution system.
 */
async function resolveHostname(hostname: Hostname): Promise<Host> {
  const result = await dns.promises.lookup(hostname, {
    family: 0,
    all: false,
    verbatim: true,
  });
  return result.address as Host;
}

/**
 * This will resolve a Host or Hostname to Host and `udp4` or `udp6`.
 * The `resolveHostname` can be overridden.
 */
async function resolveHost(
  host: Host | Hostname,
  resolveHostname: (hostname: Hostname) => Host | PromiseLike<Host>,
): Promise<[Host, 'udp4' | 'udp6']> {
  if (isIPv4(host)) {
    return [host as Host, 'udp4'];
  } else if (isIPv6(host)) {
    return [host as Host, 'udp6'];
  } else {
    host = await resolveHostname(host as Hostname);
    return resolveHost(host, resolveHostname);
  }
}

/**
 * This gets the network interfaces from Node's os.
 */
function getNetworkInterfaces(): NetworkInterfaces {
  return os.networkInterfaces();
}

function getHostname(): Hostname {
  return os.hostname() as Hostname;
}

/**
 * Convert callback-style to promise-style
 * If this is applied to overloaded function
 * it will only choose one of the function signatures to use
 */
function promisify<
  T extends Array<unknown>,
  P extends Array<unknown>,
  R extends T extends [] ? void : T extends [unknown] ? T[0] : T,
>(
  f: (...args: [...params: P, callback: Callback<T>]) => unknown,
): (...params: P) => Promise<R> {
  // Uses a regular function so that `this` can be bound
  return function (...params: P): Promise<R> {
    return new Promise((resolve, reject) => {
      const callback = (error, ...values) => {
        if (error != null) {
          return reject(error);
        }
        if (values.length === 0) {
          (resolve as () => void)();
        } else if (values.length === 1) {
          resolve(values[0] as R);
        } else {
          resolve(values as R);
        }
        return;
      };
      params.push(callback);
      f.apply(this, params);
    });
  };
}

/**
 * Deconstructed promise
 */
function promise<T = void>(): PromiseDeconstructed<T> {
  let resolveP, rejectP;
  const p = new Promise<T>((resolve, reject) => {
    resolveP = resolve;
    rejectP = reject;
  });
  return {
    p,
    resolveP,
    rejectP,
  };
}

/**
 * Zero-copy wraps ArrayBuffer-like objects into Buffer
 * This supports ArrayBuffer, TypedArrays and the NodeJS Buffer
 */
function bufferWrap(
  array: BufferSource,
  offset?: number,
  length?: number,
): Buffer {
  if (Buffer.isBuffer(array)) {
    return array;
  } else if (ArrayBuffer.isView(array)) {
    return Buffer.from(
      array.buffer,
      offset ?? array.byteOffset,
      length ?? array.byteLength,
    );
  } else {
    return Buffer.from(array, offset, length);
  }
}

/**
 * Given host and port, create an address string.
 */
function buildAddress(host: string, port: number = 0): string {
  let address: string;
  if (isIPv4(host)) {
    address = `${host}:${port}`;
  } else if (isIPv6(host)) {
    address = `[${host}]:${port}`;
  } else {
    address = `${host}:${port}`;
  }
  return address;
}

function isHostWildcard(host: Host): boolean {
  return (
    host === '0.0.0.0' ||
    host === '::' ||
    host === '::0' ||
    host === '::ffff:0.0.0.0' ||
    host === '::ffff:0:0'
  );
}

/**
 * Zero IPs should be resolved to localhost when used as the target
 */
function resolvesZeroIP(host: Host): Host {
  const zeroIPv4 = new IPv4('0.0.0.0');
  // This also covers `::0`
  const zeroIPv6 = new IPv6('::');
  if (isIPv4MappedIPv6(host)) {
    const ipv4 = fromIPv4MappedIPv6(host);
    if (new IPv4(ipv4).isEquals(zeroIPv4)) {
      return toIPv4MappedIPv6Dec('127.0.0.1');
    } else {
      return host;
    }
  } else if (isIPv4(host) && new IPv4(host).isEquals(zeroIPv4)) {
    return '127.0.0.1' as Host;
  } else if (isIPv6(host) && new IPv6(host).isEquals(zeroIPv6)) {
    return '::1' as Host;
  } else {
    return host;
  }
}

// Default ResourceRecord ttl is 120 seconds
function toHostResourceRecords(
  hosts: Host[],
  hostname: Hostname,
  flush: boolean = false,
  ttl: number = 120,
): StringRecord[] {
  return hosts.map((host) => ({
    name: hostname,
    type: isIPv4(host) ? RType.A : RType.AAAA,
    class: RClass.IN,
    ttl, // Default StringRecord ttl is 120 seconds
    data: host,
    flush,
  }));
}

function isService(service: any): service is Service {
  return (
    typeof service.hostname === 'string' &&
    typeof service.name === 'string' &&
    typeof service.type === 'string' &&
    typeof service.protocol === 'string' &&
    typeof service.port === 'number'
  );
}

// Default ResourceRecord ttl is 120 seconds
function toServiceResourceRecords(
  services: Service[],
  hostname: Hostname,
  flush: boolean = false,
  ttl: number = 120,
): ResourceRecord[] {
  return services.flatMap((service) => {
    const serviceDomain = `_${service.type}._${service.protocol}.local`;
    const fdqn = `${service.name}.${serviceDomain}`;
    return [
      {
        name: fdqn,
        type: RType.SRV,
        class: RClass.IN,
        ttl: ttl,
        flush: flush,
        data: {
          priority: 0,
          weight: 0,
          port: service.port,
          target: hostname,
        },
      },
      {
        name: fdqn,
        type: RType.TXT,
        class: RClass.IN,
        ttl: ttl,
        flush: flush,
        data: service.txt ?? {},
      },
      {
        name: serviceDomain,
        type: RType.PTR,
        class: RClass.IN,
        ttl: ttl,
        flush: flush,
        data: fdqn,
      },
      {
        name: '_services._dns-sd._udp.local',
        type: RType.PTR,
        class: RClass.IN,
        ttl: ttl,
        flush: flush,
        data: serviceDomain,
      },
    ];
  });
}

export {
  isIPv4,
  isIPv6,
  isIPv4MappedIPv6,
  isIPv4MappedIPv6Hex,
  isIPv4MappedIPv6Dec,
  toIPv4MappedIPv6Dec,
  toIPv4MappedIPv6Hex,
  fromIPv4MappedIPv6,
  toCanonicalIp,
  resolveHostname,
  resolveHost,
  getNetworkInterfaces,
  getHostname,
  promisify,
  promise,
  bufferWrap,
  buildAddress,
  resolvesZeroIP,
  isHostWildcard,
  toHostResourceRecords,
  isService,
  toServiceResourceRecords,
};
