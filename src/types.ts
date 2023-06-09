import { OPTRecord, ResourceRecord, RType } from './dns';

/**
 * Opaque types are wrappers of existing types
 * that require smart constructors
 */
type Opaque<K, T> = T & { readonly [brand]: K };
declare const brand: unique symbol;

/**
 * Generic callback
 */
type Callback<P extends Array<any> = [], R = any, E extends Error = Error> = {
  (e: E, ...params: Partial<P>): R;
  (e?: null | undefined, ...params: P): R;
};

/**
 * Deconstructed promise
 */
type PromiseDeconstructed<T> = {
  p: Promise<T>;
  resolveP: (value: T | PromiseLike<T>) => void;
  rejectP: (reason?: any) => void;
};

/**
 * Host is always an IP address
 */
type Host = Opaque<'Host', string>;

/**
 * Hostnames are resolved to IP addresses
 */
type Hostname = Opaque<'Hostname', string>;

/**
 * Ports are numbers from 0 to 65535
 */
type Port = Opaque<'Port', number>;

/**
 * Combination of `<HOST>:<PORT>`
 */
type Address = Opaque<'Address', string>;

type Service = {
  name: string;
  type: string;
  protocol: 'udp' | 'tcp';
  port: Port;
  txt?: Record<string, string>;
  hostname: Hostname;
  hosts: Host[];
};

type NetworkAddress = {
  address: string;
  family: 'IPv4' | 'IPv6';
  internal: boolean;
  netmask: string;
};

type NetworkInterfaces = Record<string, Array<NetworkAddress> | undefined>;

export type {
  Opaque,
  Callback,
  PromiseDeconstructed,
  Host,
  Hostname,
  Port,
  Address,
  Service,
  NetworkAddress,
  NetworkInterfaces,
};
