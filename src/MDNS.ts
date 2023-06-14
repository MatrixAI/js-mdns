import type {
  Host,
  Hostname,
  Port,
  Service,
  ServiceConstructor,
} from './types';
import type {
  Packet,
  QuestionRecord,
  ResourceRecord,
  StringRecord,
} from './dns';
import * as dgram from 'dgram';
import os from 'os';
import { CreateDestroyStartStop } from '@matrixai/async-init/dist/CreateDestroyStartStop';
import { Timer } from '@matrixai/timer';
import Logger from '@matrixai/logger';
import * as utils from './utils';
import * as errors from './errors';
import {
  generatePacket,
  isStringRecord,
  PacketOpCode,
  PacketType,
  parsePacket,
  QClass,
  QType,
  RClass,
  RCode,
  RType,
} from './dns';
import { MDNSServiceEvent } from './events';

const MDNS_TTL = 255;

// RFC 6762 10. TTLs of various records
const HOSTNAME_RR_TTL = 120;
const OTHER_RR_TTL = 4500;

interface MDNS extends CreateDestroyStartStop {}
@CreateDestroyStartStop(
  new errors.ErrorMDNSRunning(),
  new errors.ErrorMDNSDestroyed(),
)
class MDNS extends EventTarget {
  protected services: Service[] = [];
  protected resourceRecordCache: ResourceRecord[] = [];
  protected resourceRecordCacheDirty = true;

  protected externalResourceRecordCache: Record<
    string,
    { record: ResourceRecord; timer: Timer }[]
  > = {};
  protected queries: Map<string, { record: QuestionRecord; timer: Timer }> =
    new Map();

  protected boundHosts: Host[] = [];

  protected socket: dgram.Socket;
  protected _host: Host;
  protected _port: Port;
  protected _type: 'ipv4' | 'ipv6' | 'ipv4&ipv6';
  protected _group: Host[];
  protected _hostname: Hostname;

  protected logger: Logger;

  protected resolveHostname: (hostname: Hostname) => Host | PromiseLike<Host>;

  protected socketBind: (port: number, host: string) => Promise<void>;
  protected socketClose: () => Promise<void>;
  protected socketSend: (...params: Array<any>) => Promise<number>;

  public static createMDNS({
    resolveHostname = utils.resolveHostname,
    logger = new Logger(`${this.name}`),
  }: {
    resolveHostname?: (hostname: Hostname) => Host | PromiseLike<Host>;
    logger?: Logger;
  }) {
    const mdns = new this({
      resolveHostname,
      logger,
    });
    return mdns;
  }

  public constructor({ resolveHostname, logger }) {
    super();
    this.resolveHostname = resolveHostname;
    this.logger = logger;
  }

  // Starts the MDNS responder. This will work differently on different platforms. For platforms that already have a system-wide MDNS responder, this will do nothing. Else, sockets will be bound to interfaces for interacting with the multicast group address.
  public async start({
    host = '::' as Host,
    port = 5353 as Port,
    ipv6Only = false,
    group = ['224.0.0.251', 'ff02::fb'] as Host[],
    hostname = `${os.hostname()}.local` as Hostname,
    reuseAddr = true,
  }: {
    host?: Host | Hostname;
    port?: Port;
    ipv6Only?: boolean;
    group?: Host[];
    hostname?: Hostname;
    reuseAddr?: boolean;
  }): Promise<void> {
    let address = utils.buildAddress(host, port);
    this.logger.info(`Start ${this.constructor.name} on ${address}`);
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
    this._hostname = hostname;

    this.socket.setTTL(MDNS_TTL);
    this.socket.setMulticastTTL(MDNS_TTL);
    this.socket.setMulticastLoopback(true);
    const ifaces = Object.values(os.networkInterfaces()).flatMap((iface) =>
      typeof iface === 'undefined' ? [] : iface,
    );
    if (utils.isHostWildcard(this._host)) {
      for (const iface of ifaces) {
        if (this._type === 'ipv4' && iface.family !== 'IPv4') continue;
        if (this._type === 'ipv6' && iface.family !== 'IPv6') continue;
        this.registerHost(iface.address as Host);
      }
    } else {
      this.registerHost(this._host);
    }

    this.socket.on('message', (...p) => this.handleSocketMessage(...p));
    this.socket.on('error', (...p) => this.handleSocketError(...p));
    address = utils.buildAddress(this._host, this._port);
    this.logger.info(`Started ${this.constructor.name} on ${address}`);

    const hostRecords: StringRecord[] = utils.toHostResourceRecords(
      this.boundHosts,
      this._hostname,
      true,
    );
    const packet: Packet = {
      id: 0,
      flags: {
        opcode: PacketOpCode.QUERY,
        rcode: RCode.NoError,
        type: PacketType.RESPONSE,
      },
      questions: [],
      answers: hostRecords,
      additionals: [],
      authorities: [],
    };
    this.advertise(packet);
  }

  private registerHost(host: Host) {
    for (const group of this._group) {
      try {
        if (utils.isIPv6(host) && utils.isIPv6(group)) {
          this.socket.addMembership(group);
        } else if (utils.isIPv4(host) && utils.isIPv4(group)) {
          this.socket.addMembership(group);
        }
      } catch (err) {}
    }
    this.boundHosts.push(host);
  }

  private advertise(packet: Packet) {
    const advertisement = () => this.sendPacket(packet);
    advertisement().then(async () => {
      await new Timer(advertisement, 1000);
    });
  }

  private async sendPacket(packet: Packet) {
    const message = generatePacket(packet);
    for (const group of this._group) {
      let g = group;
      if (this._type === 'ipv4' && !utils.isIPv4(g)) continue;
      if (this._type === 'ipv6' && !utils.isIPv6(g)) continue;
      if (this._type === 'ipv4&ipv6' && utils.isIPv4(g)) {
        g = utils.toIPv4MappedIPv6Dec(group);
      }
      await this.socketSend(message, this._port, g);
    }
  }

  private async handleSocketMessage(msg: Buffer, rinfo: dgram.RemoteInfo) {
    let packet: Packet | undefined;
    try {
      packet = parsePacket(msg);
    } catch (err) {
      this.logger.warn(err);
    }
    if (typeof packet === 'undefined') return;
    if (packet.flags.type === PacketType.QUERY) {
      await this.handleSocketMessageQuery(packet, rinfo);
    } else {
      await this.handleSocketMessageResponse(packet, rinfo);
    }
  }

  private async handleSocketMessageQuery(
    packet: Packet,
    rinfo: dgram.RemoteInfo,
  ) {
    if (packet.flags.type !== PacketType.QUERY) return;
    const answerResourceRecords: ResourceRecord[] = [];
    const additionalResourceRecords: Map<string, ResourceRecord> = new Map();

    if (this.resourceRecordCacheDirty) {
      this.resourceRecordCacheDirty = false;
      const hostResourceRecords = utils.toHostResourceRecords(
        this.boundHosts,
        this._hostname,
      );
      const toServiceResourceRecords = utils.toServiceResourceRecords(
        this.services,
        this._hostname,
      );
      this.resourceRecordCache =
        toServiceResourceRecords.concat(hostResourceRecords);
    }

    for (const question of packet.questions) {
      const foundRecord = this.resourceRecordCache.find(
        (record) =>
          record.name === question.name &&
          ((record.type as number) === question.type ||
            question.type === QType.ANY) &&
          (((record as any).class as number) === question.class ||
            question.class === QClass.ANY),
      );
      if (foundRecord) {
        answerResourceRecords.push(foundRecord);

        let additionalResourceRecordCache: ResourceRecord[] = [];
        // RFC 6763 12.1. Additionals in PTR
        if (question.type === QType.PTR) {
          additionalResourceRecordCache = this.resourceRecordCache.filter(
            (record) =>
              (record.type === RType.SRV && record.name === foundRecord.data) ||
              (record.type === RType.TXT && record.name === foundRecord.data) ||
              record.type === RType.A ||
              record.type === RType.AAAA,
          );
        }
        // RFC 6763 12.2. Additionals in SRV
        else if (question.type === QType.SRV) {
          additionalResourceRecordCache = this.resourceRecordCache.filter(
            (record) => record.type === RType.A || record.type === RType.AAAA,
          );
        }
        // RFC 6762 6.2. Additionals in A
        else if (question.type === QType.A) {
          additionalResourceRecordCache = this.resourceRecordCache.filter(
            (record) => record.type === RType.AAAA,
          );
        }
        // RFC 6762 6.2. Additionals in AAAA
        else if (question.type === QType.AAAA) {
          additionalResourceRecordCache = this.resourceRecordCache.filter(
            (record) => record.type === RType.A,
          );
        }
        for (const additionalResourceRecord of additionalResourceRecordCache) {
          const additionalResourceRecordKey = utils.toRecordKey(
            additionalResourceRecord,
          );
          if (!additionalResourceRecords.has(additionalResourceRecordKey)) {
            additionalResourceRecords.set(
              additionalResourceRecordKey,
              additionalResourceRecord,
            );
          }
        }
      }
    }

    if (answerResourceRecords.length === 0) return;

    const responsePacket: Packet = {
      id: 0,
      flags: {
        opcode: PacketOpCode.QUERY,
        rcode: RCode.NoError,
        type: PacketType.RESPONSE,
      },
      questions: [],
      answers: answerResourceRecords,
      additionals: [...additionalResourceRecords.values()],
      authorities: [],
    };
    if (this.socket) {
      await this.sendPacket(responsePacket);
    }
  }

  private async handleSocketMessageResponse(
    packet: Packet,
    rinfo: dgram.RemoteInfo,
  ) {
    const dirtiedServiceFdqns: string[] = [];

    // Sort by type descending so that SRV records are processed BEFORE A/AAAA records
    for (const record of packet.answers
      .concat(packet.additionals)
      .sort((a, b) => b.type - a.type)) {
      let serviceFqdn: string | undefined;
      if (record.type === RType.SRV || record.type === RType.TXT) {
        serviceFqdn = record.name;
      } else if (
        record.type === RType.PTR &&
        record.name !== '_services._dns-sd._udp.local'
      ) {
        serviceFqdn = record.data;
      } else if (record.type === RType.A || record.type === RType.AAAA) {
        const externalRecords = Object.values(this.externalResourceRecordCache)
          .flat()
          .map((wrapper) => wrapper.record);
        const srvRecord = externalRecords.find(
          (externalRecord) =>
            externalRecord.type === RType.SRV &&
            externalRecord.data.target === record.name,
        );
        // this needs to be changed, otherwise one hostname cant have multiple services.
        if (typeof srvRecord !== 'undefined') serviceFqdn = srvRecord.name;
      }
      if (typeof serviceFqdn === 'undefined') continue;
      if (!(serviceFqdn in this.externalResourceRecordCache)) {
        this.externalResourceRecordCache[serviceFqdn] = [];
      }
      const existingRecordIndex = this.externalResourceRecordCache[
        serviceFqdn
      ].findIndex(
        (wrapper) =>
          wrapper.record.name === record.name &&
          wrapper.record.type === record.type &&
          (wrapper.record as any).class === (record as any).class,
      );

      // If the record exists and is being flushed, delete it
      if ((record as any).flush) {
        if (existingRecordIndex !== -1) {
          this.externalResourceRecordCache[serviceFqdn][
            existingRecordIndex
          ].timer.cancel();
          this.externalResourceRecordCache[serviceFqdn].splice(
            existingRecordIndex,
            1,
          );
          if ((record as any).ttl === 0) {
            dirtiedServiceFdqns.push(serviceFqdn);
            continue;
          }
        }
      }
      // If the record is not being flushed and already exists, skip it
      else if (existingRecordIndex !== -1) {
        continue;
      }

      // If the record is either not being flushed and does not exist, or exists and is being flushed add it
      this.externalResourceRecordCache[serviceFqdn].push({
        record,
        timer: new Timer(async () => {
          if (
            typeof serviceFqdn === 'string' &&
            serviceFqdn in this.externalResourceRecordCache
          ) {
            const existingRecordIndex = this.externalResourceRecordCache[
              serviceFqdn
            ].findIndex(
              (wrapper) =>
                wrapper.record.name === record.name &&
                wrapper.record.type === record.type &&
                (wrapper.record as any).class === (record as any).class,
            );
            if (existingRecordIndex !== -1) {
              this.externalResourceRecordCache[serviceFqdn].splice(
                existingRecordIndex,
                1,
              );
              await this.processDirtiedServices([serviceFqdn]);
            }
          }
        }, (record as any).ttl * 1000),
      });
      dirtiedServiceFdqns.push(serviceFqdn);
    }

    await this.processDirtiedServices(dirtiedServiceFdqns);

    if (packet.questions.length !== 0) {
      await this.handleSocketMessageQuery(packet, rinfo);
    }
  }

  private async processDirtiedServices(dirtiedServiceFdqns: string[]) {
    for (const dirtiedServiceFdqn of dirtiedServiceFdqns) {
      const wrappedService = utils.fromServiceResourceRecords(
        this.externalResourceRecordCache[dirtiedServiceFdqn].map(
          (wrapper) => wrapper.record,
        ),
      );
      if (wrappedService.remainderQuestionRecords.length !== 0) {
        const queryPacket: Packet = {
          id: 0,
          flags: {
            opcode: PacketOpCode.QUERY,
            rcode: RCode.NoError,
            type: PacketType.QUERY,
          },
          questions: wrappedService.remainderQuestionRecords,
          answers: [],
          additionals: [],
          authorities: [],
        };
        await this.sendPacket(queryPacket);
      }
      if (typeof wrappedService.service !== 'undefined') {
        this.dispatchEvent(
          new MDNSServiceEvent({ detail: wrappedService.service }),
        );
      }
      // If the service is being flushed with ttl=0, delete it and servicedelete event
    }
  }

  private async handleSocketError(err: any) {}

  // Unregister all services, hosts, and sockets. For platforms with a built-in mDNS responder, this will not actually stop the responder.
  public async stop(): Promise<void> {
    const hostResourceRecords = utils.toHostResourceRecords(
      this.boundHosts,
      this._hostname,
      true,
      0,
    );
    const toServiceResourceRecords = utils.toServiceResourceRecords(
      this.services,
      this._hostname,
      true,
      0,
    );
    const allFlushedResourceRecords =
      toServiceResourceRecords.concat(hostResourceRecords);
    const goodbyePacket: Packet = {
      id: 0,
      flags: {
        opcode: PacketOpCode.QUERY,
        rcode: RCode.NoError,
        type: PacketType.RESPONSE,
      },
      questions: [],
      answers: allFlushedResourceRecords,
      additionals: [],
      authorities: [],
    };
    await this.sendPacket(goodbyePacket);
    for (const query of this.queries.values()) {
      query.timer.cancel();
    }
    await this.socketClose();
  }

  public async destroy(): Promise<void> {
    await this.stop();
    this.resourceRecordCacheDirty = true;
    this.resourceRecordCache = [];
    this.services = [];
    this.boundHosts = [];
  }

  // The most important method, this is used to register a service. All platforms support service registration of some kind. Note that some platforms may resolve service name conflicts automatically. This will have to be dealt with later. The service handle has a method that is able to then later unregister the service.
  public registerService(serviceOptions: ServiceConstructor) {
    const service: Service = {
      hostname: this._hostname,
      ...serviceOptions,
    };

    this.services.push(service);
    this.resourceRecordCacheDirty = true;
    const advertisePacket: Packet = {
      id: 0,
      flags: {
        opcode: PacketOpCode.QUERY,
        rcode: RCode.NoError,
        type: PacketType.RESPONSE,
      },
      questions: [],
      answers: utils.toServiceResourceRecords([service], this._hostname, true),
      additionals: [],
      authorities: [],
    };
    this.advertise(advertisePacket);
  }

  public unregisterService(
    name: string,
    type: string,
    protocol: 'udp' | 'tcp',
  ) {
    const serviceIndex = this.services.findIndex(
      (s) => s.name === name && s.type === type && s.protocol === protocol,
    );
    if (serviceIndex === -1) throw new Error('Service not found'); // Make this an mdns error later
    const removedServices = this.services.splice(serviceIndex, 1);
    this.resourceRecordCacheDirty = true;
    const advertisePacket: Packet = {
      id: 0,
      flags: {
        opcode: PacketOpCode.QUERY,
        rcode: RCode.NoError,
        type: PacketType.RESPONSE,
      },
      questions: [],
      answers: utils.toServiceResourceRecords(
        removedServices,
        this._hostname,
        true,
        0,
      ),
      additionals: [],
      authorities: [],
    };
    this.advertise(advertisePacket);
  }

  // Query for all services of a type and protocol, the results will be emitted to eventtarget of the instance of this class.
  public query(type: string, protocol: 'udp' | 'tcp') {
    const serviceDomain = `_${type}._${protocol}.local`;
    const questionRecord: QuestionRecord = {
      name: serviceDomain,
      type: QType.PTR,
      class: QClass.IN,
      unicast: false,
    };
    const recordKey = utils.toRecordKey(questionRecord);
    const queryPacket: Packet = {
      id: 0,
      flags: {
        opcode: PacketOpCode.QUERY,
        rcode: RCode.NoError,
        type: PacketType.QUERY,
      },
      questions: [questionRecord],
      answers: [],
      additionals: [],
      authorities: [],
    };
    const querierFn = async (iteration: number = 1) => {
      await this.sendPacket(queryPacket);
      this.queries.delete(recordKey);
      // Set ceiling to 1 hr.
      this.queries.set(recordKey, {
        record: questionRecord,
        timer: new Timer(
          () => querierFn(iteration < 3600 ? iteration * 2 : 3600),
          iteration * 1000,
        ),
      });
    };
    querierFn();
  }
}

export default MDNS;
