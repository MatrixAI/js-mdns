import type {
  Callback,
  Host,
  Hostname,
  NetworkInterfaces,
  Port,
  PromiseDeconstructed,
  Service,
} from './types';
import type { StringRecord, ResourceRecord } from '@/dns';
import type dgram from 'dgram';
import os from 'os';
import { IPv6, Validator } from 'ip-num';
import { RType, RClass } from '@/dns';

/**
 * Is it a valid Port between 0 and 65535?
 */
function isPort(port: number): port is Port {
  return port >= 0 && port <= 65535;
}

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

/**
 * This gets the network interfaces from Node's os.
 */
function getNetworkInterfaces(): NetworkInterfaces {
  return os.networkInterfaces() as NetworkInterfaces;
}

function getHostname(): Hostname {
  return os.hostname() as Hostname;
}

function getPlatform():
  | 'aix'
  | 'android'
  | 'darwin'
  | 'freebsd'
  | 'linux'
  | 'openbsd'
  | 'sunos'
  | 'win32' {
  return os.platform() as any;
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

// Default ResourceRecord ttl is 120 seconds
function toHostResourceRecords(
  hosts: Array<Host>,
  hostname: Hostname,
  flush: boolean = false,
  ttl: number = 120,
): Array<StringRecord> {
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
  services: Array<Service>,
  hostname: Hostname,
  flush: boolean = false,
  ttl: number = 120,
): Array<ResourceRecord> {
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

async function bindSocket(
  socket: dgram.Socket,
  port: number,
  address?: string,
): Promise<{ send: any; close: any }> {
  const socketBind = promisify(socket.bind).bind(socket);
  const socketClose = promisify(socket.close).bind(socket);
  const socketSend = promisify(socket.send).bind(socket);
  const { p: errorP, rejectP: rejectErrorP } = promise();
  socket.once('error', rejectErrorP);
  const socketBindP = socketBind(port, address);
  await Promise.race([socketBindP, errorP]);
  return { send: socketSend, close: socketClose };
}

/**
 * Returns a random unique unsigned 16 bit integer.
 */
function getRandomPacketId(): number {
  return Math.floor(Math.random() * 65535);
}

export {
  isPort,
  isIPv4,
  isIPv6,
  isIPv4MappedIPv6,
  getNetworkInterfaces,
  getHostname,
  getPlatform,
  promisify,
  promise,
  toHostResourceRecords,
  isService,
  toServiceResourceRecords,
  bindSocket,
  getRandomPacketId,
};
