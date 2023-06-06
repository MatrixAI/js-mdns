import { CreateDestroyStartStop } from '@matrixai/async-init/dist/CreateDestroyStartStop';
import { createSocket } from 'dgram';
import { networkInterfaces } from 'os';
import { promisify } from 'util';
import {parsePacket} from './dns';

const MDNS_TTL = 255;

// RFC 6762 10. TTLs of various records
const HOSTNAME_RR_TTL = 120;
const OTHER_RR_TTL = 4500;

interface MDNS extends CreateDestroyStartStop {}
@CreateDestroyStartStop()
class MDNS extends EventTarget {
  hostname: string;
  group: string[];
  host: string;
  port: number;
  reuseAddr: boolean;
  resolveHostname: boolean;

  public static createMDNS({
    group = ["224.0.0.251", "ff02::fb"],
    host = "::",
    port = 5353,
    reuseAddr = true,
    resolveHostname = true,
  } : {
    group?: string | string[]
    host?: string
    port?: number
    reuseAddr?: boolean
    resolveHostname?: boolean
  }) {
    const mdns = new this({
      hostname: 'abc.local',
      group: Array.isArray(group) ? group : [group],
      host,
      port,
      reuseAddr,
      resolveHostname,
    });
    return mdns;
  }

  public constructor({
    hostname,
    group,
    host,
    port,
    reuseAddr,
    resolveHostname,
  }) {
    super();
    this.hostname = hostname;
    this.group = group;
    this.host = host;
    this.port = port;
    this.reuseAddr = reuseAddr;
    this.resolveHostname = resolveHostname;
  }

  // Starts the MDNS responder. This will work differently on different platforms. For platforms that already have a system-wide MDNS responder, this will do nothing. Else, sockets will be bound to interfaces for interacting with the multicast group address.
  public async start(): Promise<void> {
    const socket = createSocket({ type: 'udp4', reuseAddr: true });
    socket.addListener('message', (buffer, rinfo) => {
      try {
        const packet = parsePacket(buffer);
        console.log(packet);
        // if (packet.type === 'query') {
        //   this.handleQuery(packet, rinfo);
        // } else {
        // }
      } catch (e) {}
    });
    await promisify(socket.bind).bind(socket)(this.port, '0.0.0.0');
    socket.addMembership(this.group[0]);
    socket.setTTL(MDNS_TTL);
    socket.setMulticastTTL(MDNS_TTL);
    socket.setMulticastLoopback(true);
  }

  // Unregister all services, hosts, and sockets. For platforms with a built-in mDNS responder, this will not actually stop the responder.
  public async stop(): Promise<void> {}

  public async destroy(): Promise<void> {}

  // The most important method, this is used to register a service. All platforms support service registration of some kind. Note that some platforms may resolve service name conflicts automatically. This will have to be dealt with later. The service handle has a method that is able to then later unregister the service.
  async registerService (options: {
    name: string;
    type: string;
    protocol: 'udp' | 'tcp';
    port: number;
    txt?: Record<string, string>;
  }): Promise<void> {

  };

  async unregisterService (
    name: string,
    type: string,
    protocol: 'udp' | 'tcp',
  ): Promise<void> {

  }

  // Query for all services of a type and protocol, the results will be emitted to eventtarget of the instance of this class.
  queryServices: (type: string, protocol: 'udp' | 'tcp') => Promise<void>;
}

export default MDNS;
