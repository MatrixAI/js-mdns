import * as dgram from 'dgram';
import os from 'os';
import * as utils from './utils';
import * as errors from './errors';
import { CreateDestroyStartStop } from '@matrixai/async-init/dist/CreateDestroyStartStop';
import { generatePacket, Packet, PacketOpCode, PacketType, parsePacket, QClass, QType, RClass, RCode, ResourceRecord, RType, StringRecord } from './dns';
import { Host, Hostname, Port, Service } from './types';
import { Timer } from '@matrixai/timer';

const MDNS_TTL = 255;

// RFC 6762 10. TTLs of various records
const HOSTNAME_RR_TTL = 120;
const OTHER_RR_TTL = 4500;

interface MDNS extends CreateDestroyStartStop {}
@CreateDestroyStartStop(
  new errors.ErrorMDNSRunning(),
  new errors.ErrorMDNSDestroyed()
)
class MDNS extends EventTarget {
  protected hostname: string;
  protected services: Service[] = [];
  protected boundHosts: Host[] = [];

  protected socket: dgram.Socket;
  protected _host: Host;
  protected _port: Port;
  protected _type: 'ipv4' | 'ipv6' | 'ipv4&ipv6';
  protected _group: Host[];

  protected resolveHostname: (hostname: Hostname) => Host | PromiseLike<Host>;

  protected socketBind: (port: number, host: string) => Promise<void>;
  protected socketClose: () => Promise<void>;
  protected socketSend: (...params: Array<any>) => Promise<number>;

  public static createMDNS({
    resolveHostname = utils.resolveHostname,
  }: {
    resolveHostname?: (hostname: Hostname) => Host | PromiseLike<Host>;
  }) {
    const mdns = new this({
      resolveHostname,
    });
    return mdns;
  }

  public constructor({
    resolveHostname,
  }) {
    super();
    this.resolveHostname = resolveHostname;
  }

  // Starts the MDNS responder. This will work differently on different platforms. For platforms that already have a system-wide MDNS responder, this will do nothing. Else, sockets will be bound to interfaces for interacting with the multicast group address.
  public async start({
    host = '::' as Host,
    port = 5353 as Port,
    ipv6Only = false,
    group = ['224.0.0.251', 'ff02::fb'] as Host[],
    reuseAddr = true,
  }: {
    host?: Host | Hostname;
    port?: Port;
    ipv6Only?: boolean;
    group?: Host[];
    reuseAddr?: boolean;
  }): Promise<void> {
    let address = utils.buildAddress(host, port);
    console.log(`Start ${this.constructor.name} on ${address}`);
    // Resolves the host which could be a hostname and acquire the type.
    // If the host is an IPv4 mapped IPv6 address, then the type should be udp6.
    const [host_, udpType] = await utils.resolveHost(
      host,
      this.resolveHostname,
    );
    this.socket = dgram.createSocket({
      type: udpType,
      reuseAddr,
      ipv6Only,
    });
    this.socketBind = utils.promisify(this.socket.bind).bind(this.socket);
    this.socketClose = utils.promisify(this.socket.close).bind(this.socket);
    this.socketSend = utils.promisify(this.socket.send).bind(this.socket);
    const { p: errorP, rejectP: rejectErrorP } = utils.promise();
    this.socket.once('error', rejectErrorP);
    // This resolves DNS via `getaddrinfo` under the hood.
    // It which respects the hosts file.
    // This makes it equivalent to `dns.lookup`.
    const socketBindP = this.socketBind(port, host_);
    try {
      await Promise.race([socketBindP, errorP]);
    } catch (e) {
      // Possible binding failure due to EINVAL or ENOTFOUND.
      // EINVAL due to using IPv4 address where udp6 is specified.
      // ENOTFOUND when the hostname doesn't resolve, or doesn't resolve to IPv6 if udp6 is specified
      // or doesn't resolve to IPv4 if udp4 is specified.
      throw new errors.ErrorMDNSInvalidBindAddress(
        host !== host_
          ? `Could not bind to resolved ${host} -> ${host_}`
          : `Could not bind to ${host}`,
        {
          cause: e,
        },
      );
    }
    this.socket.removeListener('error', rejectErrorP);
    const socketAddress = this.socket.address();
    // This is the resolved IP, not the original hostname
    this._host = socketAddress.address as Host;
    this._port = socketAddress.port as Port;
    // Dual stack only exists for `::` and `!ipv6Only`
    if (host_ === '::' && !ipv6Only) {
      this._type = 'ipv4&ipv6';
    } else if (udpType === 'udp4' || utils.isIPv4MappedIPv6(host_)) {
      this._type = 'ipv4';
    } else if (udpType === 'udp6') {
      this._type = 'ipv6';
    }
    this._group = group;

    this.socket.setTTL(MDNS_TTL);
    this.socket.setMulticastTTL(MDNS_TTL);
    this.socket.setMulticastLoopback(true);
    if (utils.isHostWildcard(this._host)) {
      const ifaces = Object.values(os.networkInterfaces()).flatMap(iface => typeof iface !== "undefined" ? iface : []);
      for (const ip of ifaces) {
        if (this._type === "ipv4" && ip.family !== "IPv4") continue;
        if (this._type === "ipv6" && ip.family !== "IPv6") continue;
        this.registerHost(ip.address as Host);
      }
    }
    else {
      this.registerHost(this._host);
    }
    this.socket.addListener('message', this.handleSocketMessage);
    this.socket.addListener('error', this.handleSocketError);
    address = utils.buildAddress(this._host, this._port);
    console.log(`Started ${this.constructor.name} on ${address}`);

    const hostRecords: StringRecord[] = this.getBoundHostRecords({flush: true});
    const packet = generatePacket({
      id: 0,
      flags: {
        opcode: PacketOpCode.QUERY,
        rcode: RCode.NoError,
        type: PacketType.RESPONSE,
      },
      questions: [],
      answers: hostRecords,
      additionals: [],
      authorities: []
    });
    this.advertise(packet);
  }

  private registerHost(host: Host) {
    for (const group of this._group) {
      if (utils.isIPv6(host) && utils.isIPv6(group)) {
        this.socket.addMembership(group, host);
        console.log(group, host)
      }
      else if (utils.isIPv4(host) && utils.isIPv4(group)) {
        this.socket.addMembership(group, host);
        console.log(group, host)
      }

    }
    this.boundHosts.push(host);
  }

  private advertise(packet) {
    const advertisement = async () => {
      for (const group of this._group) {
        await this.socketSend(packet, this._port, group);
      }
    }
    advertisement().then(async () => {
      await new Timer(advertisement, 1000);
    })
  }

  private async handleSocketMessage(msg: Buffer, rinfo: dgram.RemoteInfo) {
    const packet = parsePacket(msg);
    if (packet.flags.type === PacketType.QUERY) {
      this.handleSocketMessageQuery(packet, rinfo);
    }
    else {
      this.handleSocketMessageResponse(packet, rinfo);
    }
  }

  private async handleSocketMessageQuery(
    packet: Packet,
    rinfo: dgram.RemoteInfo,
  ): Promise<void> {
    if (packet.flags.type !== PacketType.QUERY) return;
    console.log(packet);
    const answerRecords: ResourceRecord[] = [];

    const hostRecords = this.getBoundHostRecords({});
    for (const question of packet.questions) {
      const foundRecord = hostRecords.find(record =>
        record.name === question.name
        && (record.type as number === question.type || question.type === QType.ANY)
        && (record.class as number === question.class || question.class === QClass.ANY)
      );
      if (foundRecord) answerRecords.push(foundRecord);
    }
    if (answerRecords.length === 0) return;

    const responsePacket = generatePacket({
      id: 0,
      flags: {
        opcode: PacketOpCode.QUERY,
        rcode: RCode.NoError,
        type: PacketType.RESPONSE,
      },
      questions: [],
      answers: answerRecords,
      additionals: [],
      authorities: []
    });
    if (this.socket) {
      const p = utils.promisify(this.socket.send).bind(this.socket, responsePacket, this._port, utils.toIPv4MappedIPv6Dec(this._group[0]));
      await p();
    }
  }

  private async handleSocketMessageResponse(
    packet: Packet,
    rinfo: dgram.RemoteInfo
  ) {

  }

  private async handleSocketError() {

  }

  private getBoundHostRecords(options: Partial<StringRecord>) {
    const hostRecords: StringRecord[] = this.boundHosts.map(host => ({
      name: options.name ?? this.hostname,
      type: utils.isIPv4(host) ? RType.A : RType.AAAA,
      class: RClass.IN,
      ttl: options.ttl ?? HOSTNAME_RR_TTL,
      data: options.data ?? host,
      flush: options.flush ?? false
    }));
    return hostRecords;
  }

  // Unregister all services, hosts, and sockets. For platforms with a built-in mDNS responder, this will not actually stop the responder.
  public async stop(): Promise<void> {
    await this.socket.close();
  }

  public async destroy(): Promise<void> {
    await this.stop();
  }

  // The most important method, this is used to register a service. All platforms support service registration of some kind. Note that some platforms may resolve service name conflicts automatically. This will have to be dealt with later. The service handle has a method that is able to then later unregister the service.
  async registerService(service: Service): Promise<void> {
    this.services.push(service);
  }

  async unregisterService(
    name: string,
    type: string,
    protocol: 'udp' | 'tcp',
  ): Promise<void> {}

  // Query for all services of a type and protocol, the results will be emitted to eventtarget of the instance of this class.
  queryServices: (type: string, protocol: 'udp' | 'tcp') => Promise<void>;
}

export default MDNS;
