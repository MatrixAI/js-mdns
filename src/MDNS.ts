import type {
  Host,
  Hostname,
  Port,
  Service,
  ServiceOptions,
  NetworkInterfaces,
} from './types';
import type {
  CachableResourceRecord,
  Packet,
  QuestionRecord,
  ResourceRecord,
  StringRecord,
} from './dns';
import * as dgram from 'dgram';
import { StartStop, ready } from '@matrixai/async-init/dist/StartStop';
import { Timer } from '@matrixai/timer';
import Logger from '@matrixai/logger';
import Table from '@matrixai/table';
import { IPv4, IPv4Mask, IPv6, IPv6Mask } from 'ip-num';
import * as utils from './utils';
import * as errors from './errors';
import {
  generatePacket,
  PacketOpCode,
  PacketType,
  parsePacket,
  QClass,
  QType,
  RCode,
  RType,
} from './dns';
import { MDNSServiceEvent, MDNSServiceRemovedEvent } from './events';
import { MDNSCacheExpiredEvent, ResourceRecordCache } from './cache';
import { isCachableResourceRecord } from './dns';

const MDNS_TTL = 255;

// RFC 6762 10. TTLs of various records
const HOSTNAME_RR_TTL = 120;
const OTHER_RR_TTL = 4500;

interface MDNS extends StartStop {}
@StartStop()
class MDNS extends EventTarget {
  protected logger: Logger;
  protected resolveHostname: (hostname: Hostname) => Host | PromiseLike<Host>;
  protected getNetworkInterfaces: () =>
    | NetworkInterfaces
    | PromiseLike<NetworkInterfaces>;

  protected services: Array<Service> = [];
  protected localRecordCache: Array<ResourceRecord> = [];
  protected localRecordCacheDirty = true;
  // TODO: cache needs to be LRU to prevent DoS
  protected networkRecordCache: ResourceRecordCache =
    ResourceRecordCache.createMDNSCache();
  protected networkServices: Map<string, Service> = new Map();
  protected sockets: Array<dgram.Socket> = [];
  protected socketMap: WeakMap<
    dgram.Socket,
    {
      close: () => Promise<void>;
      send: (...params: Array<any>) => Promise<number>;
      networkInterfaceName: string;
      host: string;
      udpType: 'udp4' | 'udp6';
      group: Host;
    }
  > = new WeakMap();
  protected socketHostTable: Table<{
    networkInterfaceName: string;
    address: string;
    family: 'IPv4' | 'IPv6';
    netmask: string;
  }> = new Table(
    ['networkInterfaceName', 'address', 'family'],
    [
      ['networkInterfaceName'],
      ['address']
    ],
  );
  protected _host: Host;
  protected _port: Port;
  protected _type: 'ipv4' | 'ipv6' | 'ipv4&ipv6';
  protected _groups: Array<Host>;
  protected _hostname: Hostname;

  public constructor({
    resolveHostname = utils.resolveHostname,
    getNetworkInterfaces = utils.getNetworkInterfaces,
    logger,
  }: {
    resolveHostname?: (hostname: Hostname) => Host | PromiseLike<Host>;
    getNetworkInterfaces?: () =>
      | NetworkInterfaces
      | PromiseLike<NetworkInterfaces>;
    logger?: Logger;
  } = {}) {
    super();
    this.logger = logger ?? new Logger(this.constructor.name);
    this.resolveHostname = resolveHostname;
    this.getNetworkInterfaces = getNetworkInterfaces;
  }

  /**
   * Gets the bound resolved host IP (not hostname).
   * This can be the IPv4 or IPv6 address.
   * This could be a wildcard address which means all interfaces.
   * Note that `::` can mean all IPv4 and all IPv6.
   * Whereas `0.0.0.0` means only all IPv4.
   */
  @ready(new errors.ErrorMDNSNotRunning())
  public get host(): Host {
    return this._host;
  }

  /**
   * Gets the bound resolved port.
   * This cannot be `0`.
   * Because `0` is always resolved to a specific port.
   */
  @ready(new errors.ErrorMDNSNotRunning())
  public get port() {
    return this._port;
  }

  /**
   * Gets the type of socket
   * It can be ipv4-only, ipv6-only or dual stack
   */
  @ready(new errors.ErrorMDNSNotRunning())
  public get type(): 'ipv4' | 'ipv6' | 'ipv4&ipv6' {
    return this._type;
  }

  /**
   * Gets the multicast groups this socket is bound to.
   * There will always be at least 1 value.
   */
  @ready(new errors.ErrorMDNSNotRunning())
  public get groups(): ReadonlyArray<Host> {
    return this._groups;
  }

  /**
   * Starts MDNS

   * @param opts
   * @param opts.host - The host to bind to. Defaults to `::` for dual stack.
   * @param opts.port - The port to bind to. Defaults to 5353 the default MDNS port.
   * @param opts.group - The multicast group IP addresses to multi-cast on. This can have both IPv4 and IPv6.
   * @param opts.hostname - The hostname to use for the MDNS stack. Defaults to the OS hostname.
   * @param opts.reuseAddr - Allows MDNs to bind on the same port that an existing MDNS stack is already bound on. Defaults to true.
   */
  public async start({
    host = '::' as Host,
    port = 5353 as Port,
    ipv6Only = false,
    groups = ['224.0.0.251', 'ff02::fb'] as Array<Host>,
    hostname = utils.getHostname(),
    reuseAddr = true,
  }: {
    host?: Host | Hostname;
    port?: Port;
    ipv6Only?: boolean;

    groups?: Array<Host>;
    hostname?: string;
    reuseAddr?: boolean;
  }): Promise<void> {
    if (groups.length < 1) {
      throw new RangeError('Must have at least 1 multicast group');
    }

    // TODO: move this to where it is exactly needed so `hostname` should be the same property
    // MDNS requires all hostnames to have a `.local` with it
    hostname = (hostname + '.local') as Hostname;

    const address = utils.buildAddress(host, port);
    this.logger.info(`Start ${this.constructor.name} on ${address}`);

    // Resolves the host which could be a hostname and acquire the type.
    // If the host is an IPv4 mapped IPv6 address, then the type should be udp6.
    const [host_, udpType_] = await utils.resolveHost(
      host,
      this.resolveHostname,
    );
    const socketHosts: Array<[Host, 'udp4' | 'udp6', string]> = [];
    // When binding to wild card
    // We explicitly find out all the interfaces we are going to bind to
    // This is because we only want to respond on the interface where we received
    // A query or announcement from
    // This is because each network could have its own multicast group
    // And if a query is received on one network's multicast group
    // Then we want to send that back on the same network
    // Using the same interface, so a specific socket
    if (utils.isHostWildcard(host_)) {
      const networkInterfaces = await this.getNetworkInterfaces();
      for (const networkInterfaceName in networkInterfaces) {
        const networkAddresses = networkInterfaces[networkInterfaceName];
        if (networkAddresses == null) continue;
        for (const networkAddress of networkAddresses) {
          const { address, family } = networkAddress;
          if (host_ === '::' && !ipv6Only) {
            // Dual stack `::` allows both IPv4 and IPv6
            socketHosts.push([
              address as Host,
              family === 'IPv4' ? 'udp4' : 'udp6',
              networkInterfaceName,
            ]);
          } else if (host_ === '::' && ipv6Only && family === 'IPv6') {
            // Dual stack `::` with `ipv6Only` only allows IPv6 hosts
            socketHosts.push([address as Host, 'udp6', networkInterfaceName]);
          } else if (udpType_ === 'udp4' && family === 'IPv4') {
            // If `0.0.0.0`
            socketHosts.push([address as Host, udpType_, networkInterfaceName]);
          } else if (
            udpType_ === 'udp6' &&
            !utils.isIPv4MappedIPv6(host_) &&
            family === 'IPv6'
          ) {
            // If `::0`
            socketHosts.push([address as Host, udpType_, networkInterfaceName]);
          } else if (
            udpType_ === 'udp6' &&
            utils.isIPv4MappedIPv6(host_) &&
            family === 'IPv4'
          ) {
            // If `::ffff:0.0.0.0` or `::ffff:0:0`
            socketHosts.push([
              ('::ffff:' + address) as Host,
              udpType_,
              networkInterfaceName,
            ]);
          }
          this.socketHostTable.insertRow({
            ...networkAddress,
            networkInterfaceName
          });
        }
      }
      if (socketHosts.length < 1) {
        // TODO: replace this with domain specific error
        throw new RangeError(
          'Wildcard did not resolve to any network interfaces',
        );
      }
    } else {
      // this.networkInterfaceTable.insertRow({
      //   address: host_,
      //   udpType: udpType_,
      //   networkInterfaceName: '',
      // });
      socketHosts.push([host_, udpType_, '']);
    }

    // Here we create multiple sockets
    // This may only contain 1
    // or we end up with multiple sockets we are working with
    const sockets: Array<dgram.Socket> = [];
    for (const [socketHost, udpType, networkInterfaceName] of [
      ...socketHosts,
    ]) {
      const linkLocalSocketHost =
        udpType === 'udp6' && socketHost.startsWith('fe80')
          ? ((socketHost + '%' + networkInterfaceName) as Host)
          : socketHost;
      for (const group of [...groups]) {
        if (utils.isIPv4(group) && udpType !== 'udp4') continue;
        if (utils.isIPv6(group) && udpType !== 'udp6') continue;
        const linkLocalGroup =
          udpType === 'udp6' && group.startsWith('ff02')
            ? ((group + '%' + networkInterfaceName) as Host)
            : group;
        const socket = dgram.createSocket({
          type: udpType,
          reuseAddr,
          ipv6Only,
        });
        const socketBind = utils.promisify(socket.bind).bind(socket);
        const socketClose = utils.promisify(socket.close).bind(socket);
        const socketSend = utils.promisify(socket.send).bind(socket);
        const { p: errorP, rejectP: rejectErrorP } = utils.promise();
        socket.once('error', rejectErrorP);
        const socketBindP = socketBind(port);
        try {
          await Promise.race([socketBindP, errorP]);
        } catch (e) {
          for (const socket of sockets.reverse()) {
            await socket.close();
          }
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
        socket.removeListener('error', rejectErrorP);

        socket.addListener('message', (msg, rinfo) =>
          this.handleSocketMessage(msg, rinfo, socket),
        );
        socket.addListener('error', (...p) => this.handleSocketError(...p));
        socket.setMulticastInterface(linkLocalSocketHost);
        socket.addMembership(linkLocalGroup, linkLocalSocketHost);
        socket.setMulticastTTL(MDNS_TTL);
        socket.setTTL(MDNS_TTL);
        socket.setMulticastLoopback(true);

        this.socketMap.set(socket, {
          close: socketClose,
          send: socketSend,
          networkInterfaceName,
          host: socketHost,
          udpType,
          group,
        });
        sockets.push(socket);
      }
    }

    this.sockets = sockets;
    this._host = host_;
    this._port = port;
    this._groups = groups;
    this._hostname = hostname as Hostname;
    this.networkRecordCache.addEventListener("expired", (event: MDNSCacheExpiredEvent) => this.processExpiredResourceRecords(event.detail));

    // We have to figure out 1 socket at a time
    // And we have to decide what we are doing here
  }

  // Use set of timers instead instead of dangling
  private advertise(packet: Packet, socket: dgram.Socket) {
    const advertisement = async () => {
      try {
        await this.sendPacket(packet, socket);
      } catch (err) {
        if (err.code !== 'ERR_SOCKET_DGRAM_NOT_RUNNING') {
          // TODO: deal with this
        }
      }
    };
    advertisement().then(async () => {
      await new Timer(advertisement, 1000);
    });
  }

  private async sendPacket(packet: Packet, socket: dgram.Socket) {
    const message = generatePacket(packet);
    const socketWrapper = this.socketMap.get(socket);
    await socketWrapper?.send(message, this._port, socketWrapper.group);
  }

  private async handleSocketMessage(
    msg: Buffer,
    rinfo: dgram.RemoteInfo,
    socket: dgram.Socket,
  ) {

    // We check if the received message is from the same subnet in order to determine if we should respond.
    // TODO: The parsed result can be cached in future.
    try {
      const addressRowI = this.socketHostTable.whereRows(['address'], [this.socketMap.get(socket)?.host]).at(0);
      const address = addressRowI ? this.socketHostTable.getRow(addressRowI) : undefined;
      if (address != null) {
        let mask: IPv4Mask | IPv6Mask;
        let localAddress: IPv4 | IPv6;
        let remoteAddress: IPv4 | IPv6;
        if (address.family === "IPv4") {
          localAddress = IPv4.fromString(address.address);
          remoteAddress = IPv4.fromString(rinfo.address);
          mask = new IPv4Mask(address.netmask);
        }
        else {
          localAddress = IPv6.fromString(address.address);
          remoteAddress = IPv6.fromString(rinfo.address.split('%', 2)[0]);
          mask = new IPv6Mask(address.netmask);
        }
        if ((mask.getValue() & remoteAddress.getValue()) !== (mask.getValue() & localAddress.getValue())) return;
      }
    }
    catch(_err) {
      this.logger.warn("An error occurred in parsing a socket's subnet, responding anyway.");
    }

    let packet: Packet | undefined;
    try {
      packet = parsePacket(msg);
    } catch (err) {
      this.logger.warn(err);
    }
    if (packet == null) return;
    if (packet.flags.type === PacketType.QUERY) {
      await this.handleSocketMessageQuery(packet, rinfo, socket);
    } else {
      await this.handleSocketMessageResponse(packet, rinfo, socket);
    }
  }

  private async handleSocketMessageQuery(
    packet: Packet,
    rinfo: dgram.RemoteInfo,
    socket: dgram.Socket,
  ) {
    if (packet.flags.type !== PacketType.QUERY) return;
    const answerResourceRecords: ResourceRecord[] = [];
    const additionalResourceRecords: Map<string, ResourceRecord> = new Map();

    const networkInterfaceName =
      this.socketMap.get(socket)?.networkInterfaceName;

    const ips = this.socketHostTable
      .whereRows(['networkInterfaceName'], [networkInterfaceName])
      .flatMap((rI) => this.socketHostTable.getRow(rI)?.address ?? []);

    if (this.localRecordCacheDirty) {
      this.localRecordCacheDirty = false;
      this.localRecordCache = utils.toServiceResourceRecords(
        this.services,
        this._hostname,
      );
    }

    const hostResourceRecords = utils.toHostResourceRecords(
      ips as Host[],
      this._hostname,
    );
    const hostIncludedResourceRecords = this.localRecordCache.concat(hostResourceRecords);

    for (const question of packet.questions) {
      const foundRecord = hostIncludedResourceRecords.find(
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
          additionalResourceRecordCache = hostIncludedResourceRecords.filter(
            (record) =>
              (record.type === RType.SRV && record.name === foundRecord.data) ||
              (record.type === RType.TXT && record.name === foundRecord.data) ||
              record.type === RType.A ||
              record.type === RType.AAAA,
          );
        }
        // RFC 6763 12.2. Additionals in SRV
        else if (question.type === QType.SRV) {
          additionalResourceRecordCache = hostIncludedResourceRecords.filter(
            (record) => record.type === RType.A || record.type === RType.AAAA,
          );
        }
        // RFC 6762 6.2. Additionals in A
        else if (question.type === QType.A) {
          additionalResourceRecordCache = hostIncludedResourceRecords.filter(
            (record) => record.type === RType.AAAA,
          );
        }
        // RFC 6762 6.2. Additionals in AAAA
        else if (question.type === QType.AAAA) {
          additionalResourceRecordCache = hostIncludedResourceRecords.filter(
            (record) => record.type === RType.A,
          );
        }
        for (const additionalResourceRecord of additionalResourceRecordCache) {
          const additionalResourceRecordKey = JSON.stringify([
            additionalResourceRecord.name,
            additionalResourceRecord.class,
            additionalResourceRecord.type,
          ]);
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
    await this.sendPacket(responsePacket, socket);
  }

  private async handleSocketMessageResponse(
    packet: Packet,
    rinfo: dgram.RemoteInfo,
    socket: dgram.Socket,
  ) {
    await this.processIncomingResourceRecords(
      packet.answers.concat(packet.additionals),
      socket,
    );

    if (packet.questions.length !== 0) {
      await this.handleSocketMessageQuery(packet, rinfo, socket);
    }
  }

  private async processIncomingResourceRecords(
    resourceRecords: ResourceRecord[],
    socket: dgram.Socket,
  ) {
    // Filter out all records to only contain ones that are cachable (excludes NSEC, etc.)
    const cachableResourceRecords = resourceRecords.filter(isCachableResourceRecord);

    // Records with flush bit set will replace a set of records with 1 singular record
    const flushedResourceRecords = cachableResourceRecords.filter((record) => record.flush);
    this.networkRecordCache.delete(flushedResourceRecords);

    // Then set the new records. This order is crucial as to make sure that we don't delete any of the records we are newly setting.
    this.networkRecordCache.set(cachableResourceRecords);

    // We parse the resource records to figure out what service fdqns have been dirtied
    const dirtiedServiceFdqns: string[] = [];
    for (const resourceRecord of resourceRecords) {
      if (resourceRecord.type === RType.SRV || resourceRecord.type === RType.TXT) {
        dirtiedServiceFdqns.push(resourceRecord.name);
      } else if (
        resourceRecord.type === RType.PTR &&
        resourceRecord.name !== '_services._dns-sd._udp.local'
      ) {
        dirtiedServiceFdqns.push(resourceRecord.data);
      } else if (resourceRecord.type === RType.A || resourceRecord.type === RType.AAAA) {
        const relatedResourceRecords =
          this.networkRecordCache.getHostnameRelatedResourceRecords(
            resourceRecord.name as Hostname,
          );
        for (const relatedResourceRecord of relatedResourceRecords) {
          if (relatedResourceRecord.type === RType.SRV) {
            dirtiedServiceFdqns.push(relatedResourceRecord.name);
          }
        }
      }
    }

    // Process the dirtied fdqns to figure out what questions still need to be asked.
    const allRemainingQuestions: QuestionRecord[] = [];
    for (const dirtiedServiceFdqn of dirtiedServiceFdqns) {
      const partialService: Partial<Service> = {};
      const remainingQuestions: Map<QType, QuestionRecord> = new Map();
      remainingQuestions.set(QType.TXT, {
        name: dirtiedServiceFdqn,
        type: QType.TXT,
        class: QClass.IN,
        unicast: false,
      });
      remainingQuestions.set(QType.SRV, {
        name: dirtiedServiceFdqn,
        type: QType.SRV,
        class: QClass.IN,
        unicast: false,
      });
      let responseRecords = this.networkRecordCache.get([
        ...remainingQuestions.values(),
      ]);
      for (const responseRecord of responseRecords) {
        remainingQuestions.delete(responseRecord.type as number as QType);
        if (responseRecord.type === RType.TXT) {
          partialService.txt = responseRecord.data;
        } else if (responseRecord.type === RType.SRV) {
          const splitName = responseRecord.name.split('.');
          partialService.name = splitName.at(0);
          partialService.type = splitName.at(1)?.slice(1);
          partialService.protocol = splitName.at(2)?.slice(1) as any;
          partialService.port = responseRecord.data.port;
          partialService.hostname = responseRecord.data.target as Hostname;
        }
      }
      if (partialService.hostname == null) {
        allRemainingQuestions.push(...remainingQuestions.values());
        continue;
      }
      remainingQuestions.set(QType.A, {
        name: partialService.hostname,
        type: QType.A,
        class: QClass.IN,
        unicast: false,
      });
      remainingQuestions.set(QType.AAAA, {
        name: partialService.hostname,
        type: QType.AAAA,
        class: QClass.IN,
        unicast: false,
      });
      responseRecords = this.networkRecordCache.get([
        ...remainingQuestions.values(),
      ]);
      for (const responseRecord of responseRecords) {
        remainingQuestions.delete(responseRecord.type as number as QType);
        if (
          responseRecord.type === RType.A ||
          responseRecord.type === RType.AAAA
        ) {
          if (!Array.isArray(partialService.hosts)) {
            partialService.hosts = [];
          }
          partialService.hosts.push(responseRecord.data as Host);
        }
      }
      // We check if the service has been entirely built before dispatching the event that it has been created
      if (utils.isService(partialService)) {
        this.dispatchEvent(new MDNSServiceEvent({ detail: partialService }));
        this.networkServices.set(dirtiedServiceFdqn, partialService);
      }
      allRemainingQuestions.push(...remainingQuestions.values());
    }

    if (allRemainingQuestions.length !== 0) {
      await this.sendPacket(
        {
          id: 0,
          flags: {
            opcode: PacketOpCode.QUERY,
            rcode: RCode.NoError,
            type: PacketType.QUERY,
          },
          questions: allRemainingQuestions,
          answers: [],
          additionals: [],
          authorities: [],
        },
        socket,
      );
    }
  }

  // We processed expired records here. Note that this also processes records of TTL 0, as they expire after 1 second as per spec.
  private async processExpiredResourceRecords(resourceRecord: CachableResourceRecord) {
    const dirtiedServiceFdqns: string[] = [];

    // Processing record to find related fdqns
    if (resourceRecord.type === RType.SRV || resourceRecord.type === RType.TXT) {
      dirtiedServiceFdqns.push(resourceRecord.name);
    } else if (
      resourceRecord.type === RType.PTR &&
      resourceRecord.name !== '_services._dns-sd._udp.local'
    ) {
      dirtiedServiceFdqns.push(resourceRecord.data);
    } else if (resourceRecord.type === RType.A || resourceRecord.type === RType.AAAA) {
      const relatedResourceRecords =
        this.networkRecordCache.getHostnameRelatedResourceRecords(
          resourceRecord.name as Hostname,
        );
      for (const relatedResourceRecord of relatedResourceRecords) {
        if (relatedResourceRecord.type === RType.SRV) {
          dirtiedServiceFdqns.push(relatedResourceRecord.name);
        }
      }
    }

    for (const dirtiedServiceFdqn of dirtiedServiceFdqns) {
      const foundService = this.networkServices.get(dirtiedServiceFdqn);
      if (foundService == null) continue;
      this.dispatchEvent(
        new MDNSServiceRemovedEvent({ detail: foundService }),
      );
      this.networkServices.delete(dirtiedServiceFdqn);
    }
  }

  private async handleSocketError(err: any) {
    this.logger.warn(err);
  }

  // Unregister all services, hosts, and sockets. For platforms with a built-in mDNS responder, this will not actually stop the responder.
  public async stop(): Promise<void> {
    const hostResourceRecords = utils.toHostResourceRecords(
      [...this.socketHostTable].flatMap((e) => e[1].address),
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
    // TODO: stop the cache
    // await this.sendPacket(goodbyePacket);
    // await this.socketClose();
  }

  public async destroy(): Promise<void> {
    await this.stop();
    this.localRecordCacheDirty = true;
    this.localRecordCache = [];
    this.services = [];
  }

  // The most important method, this is used to register a service. All platforms support service registration of some kind. Note that some platforms may resolve service name conflicts automatically. This will have to be dealt with later. The service handle has a method that is able to then later unregister the service.
  public registerService(serviceOptions: ServiceOptions) {
    const service: Service = {
      hostname: this._hostname,
      hosts: [],
      ...serviceOptions,
    };

    this.services.push(service);
    this.localRecordCacheDirty = true;
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
    // This.advertise(advertisePacket);
  }

  public unregisterService({
    name,
    type,
    protocol,
  }: {
    name: string;
    type: string;
    protocol: 'udp' | 'tcp';
  }) {
    const serviceIndex = this.services.findIndex(
      (s) => s.name === name && s.type === type && s.protocol === protocol,
    );
    if (serviceIndex === -1) throw new Error('Service not found'); // Make this an mdns error later
    const removedServices = this.services.splice(serviceIndex, 1);
    this.localRecordCacheDirty = true;
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
    // This.advertise(advertisePacket);
  }

  // Query for all services of a type and protocol, the results will be emitted to eventtarget of the instance of this class.
  public async *query({
    type,
    protocol,
    minDelay = 1,
    maxDelay = 3600,
  }: {
    type: string;
    protocol: 'udp' | 'tcp';
    minDelay?: number;
    maxDelay?: number;
  }) {
    const serviceDomain = `_${type}._${protocol}.local`;
    const questionRecord: QuestionRecord = {
      name: serviceDomain,
      type: QType.PTR,
      class: QClass.IN,
      unicast: false,
    };
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
    let delay = minDelay;
    while (true) {
      // Await this.sendPacket(queryPacket);
      yield delay;
      if (delay < maxDelay) {
        delay *= 2;
      } else if (delay !== maxDelay) {
        delay = maxDelay;
      }
    }
  }
}

export default MDNS;
