import type {
  Host,
  Hostname,
  Port,
  Service,
  ServiceOptions,
  NetworkInterfaces,
} from './types';
import {
  CachableResourceRecord,
  Packet,
  QuestionRecord,
  RClass,
  ResourceRecord,
} from './dns';
import type { MDNSCacheExpiredEvent } from './cache';
import * as dgram from 'dgram';
import { StartStop, ready } from '@matrixai/async-init/dist/StartStop';
import { Timer } from '@matrixai/timer';
import Logger from '@matrixai/logger';
import Table from '@matrixai/table';
import { IPv4, IPv4Mask, IPv6, IPv6Mask } from 'ip-num';
import { PromiseCancellable } from '@matrixai/async-cancellable';
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
import { ResourceRecordCache } from './cache';
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

  protected localRecordCache: ResourceRecordCache;
  protected localRecordCacheDirty = true;
  protected localServices: Map<Hostname, Service> = new Map();

  protected networkRecordCache: ResourceRecordCache;
  protected networkServices: Map<Hostname, Service> = new Map();
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
    [['networkInterfaceName'], ['address']],
  );
  protected _host: Host;
  protected _port: Port;
  protected _type: 'ipv4' | 'ipv6' | 'ipv4&ipv6';
  protected _groups: Array<Host>;
  protected _hostname: Hostname;

  protected queries: Map<string, PromiseCancellable<void>> = new Map();
  protected advertisements: Map<string, PromiseCancellable<void>> = new Map();

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
            networkInterfaceName,
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
      // This.networkInterfaceTable.insertRow({
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
    this.localRecordCache = await ResourceRecordCache.createResourceRecordCache({ timerDisabled: true });
    this.networkRecordCache = await ResourceRecordCache.createResourceRecordCache();
    this.networkRecordCache.addEventListener(
      'expired',
      (event: MDNSCacheExpiredEvent) =>
        this.processExpiredResourceRecords(event.detail),
    );

    for (const socket of sockets) {
      const socketInfo = this.socketMap.get(socket);
      if (socketInfo == null) continue;
      const hostRowIs = this.socketHostTable.whereRows(["networkInterfaceName"], [socketInfo?.networkInterfaceName]);
      const addresses =  hostRowIs.flatMap((rowI) => this.socketHostTable.getRow(rowI)?.address ?? []) as Host[];
      const hostResourceRecords = utils.toHostResourceRecords(addresses, this._hostname);
      const advertisePacket: Packet = {
        id: 0,
        flags: {
          opcode: PacketOpCode.QUERY,
          rcode: RCode.NoError,
          type: PacketType.RESPONSE,
        },
        questions: [],
        answers: hostResourceRecords,
        additionals: [],
        authorities: [],
      };
      this.advertise(advertisePacket, socketInfo.host, socket);
    }

    // We have to figure out 1 socket at a time
    // And we have to decide what we are doing here
  }

  // Use set of timers instead instead of dangling
  private advertise(
    packet: Packet,
    advertisementKey: string,
    socket?: dgram.Socket,
  ) {
    const advertisement = this.advertisements.get(advertisementKey);
    if (advertisement != null) {
      advertisement.cancel();
    }

    const abortController = new AbortController();
    let timer: Timer | undefined;

    abortController.signal.addEventListener('abort', () => {
      timer?.cancel();
      this.advertisements.delete(advertisementKey);
    });

    const promise = new PromiseCancellable<void>(async (resolve, reject) => {
      await this.sendPacket(packet, socket).catch(reject);
      timer = new Timer(
        () => this.sendPacket(packet, socket).catch(reject),
        1000,
      );
      await timer;
      resolve();
    }).finally(() => this.advertisements.delete(advertisementKey));

    this.advertisements.set(advertisementKey, promise);
  }

  /**
   * If the socket is not provided, the message will be sent to all sockets.
   */
  private async sendPacket(packet: Packet, socket?: dgram.Socket) {
    const message = generatePacket(packet);
    let sockets = this.sockets;
    if (socket != null) sockets = [socket];
    await Promise.all(
      sockets.map((socket) =>
        this.socketMap
          .get(socket)
          ?.send(message, this._port, this.socketMap.get(socket)?.group),
      ),
    );
  }

  private async handleSocketMessage(
    msg: Buffer,
    rinfo: dgram.RemoteInfo,
    socket: dgram.Socket,
  ) {
    // We check if the received message is from the same subnet in order to determine if we should respond.
    // TODO: The parsed result can be cached in future.
    try {
      const addressRowI = this.socketHostTable
        .whereRows(['address'], [this.socketMap.get(socket)?.host])
        .at(0);
      const address = addressRowI
        ? this.socketHostTable.getRow(addressRowI)
        : undefined;
      if (address != null) {
        let mask: IPv4Mask | IPv6Mask;
        let localAddress: IPv4 | IPv6;
        let remoteAddress: IPv4 | IPv6;
        let remoteNetworkInterfaceName: string | undefined;
        if (address.family === 'IPv4') {
          localAddress = IPv4.fromString(address.address);
          remoteAddress = IPv4.fromString(rinfo.address);
          mask = new IPv4Mask(address.netmask);
          if (
            (mask.value & remoteAddress.value) !==
            (mask.value & localAddress.value)
          ) {
            return;
          }
        } else {
          localAddress = IPv6.fromString(address.address);
          const [remoteAddress_, remoteNetworkInterfaceName_] =
            rinfo.address.split('%', 2);
          remoteAddress = IPv6.fromString(remoteAddress_);
          mask = new IPv6Mask(address.netmask);
          remoteNetworkInterfaceName = remoteNetworkInterfaceName_;
        }
        if (
          (mask.value & remoteAddress.value) !==
          (mask.value & localAddress.value)
        ) {
          return;
        } else if (
          remoteNetworkInterfaceName != null &&
          remoteNetworkInterfaceName !== address.networkInterfaceName
        ) {
          return;
        }
      }
    } catch (_err) {
      this.logger.warn(
        "An error occurred in parsing a socket's subnet, responding anyway.",
      );
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
    _rinfo: dgram.RemoteInfo,
    socket: dgram.Socket,
  ) {
    if (packet.flags.type !== PacketType.QUERY) return;
    const answerResourceRecords: ResourceRecord[] = [];
    const additionalResourceRecords: ResourceRecord[] = [];
    const additionalQuestionRecords: QuestionRecord[] = [];
    const processedRowIs = new Set<number>();
    let hasHostRecordsBeenProcessed = false;

    const networkInterfaceName =
      this.socketMap.get(socket)?.networkInterfaceName;

    const ips = this.socketHostTable
      .whereRows(['networkInterfaceName'], [networkInterfaceName])
      .flatMap((rI) => this.socketHostTable.getRow(rI)?.address ?? []);

    if (this.localRecordCacheDirty) {
      this.localRecordCacheDirty = false;
      this.localRecordCache.clear();
      this.localRecordCache.set(
        utils.toServiceResourceRecords(
          [...this.localServices.values()],
          this._hostname,
        ) as CachableResourceRecord[]
      );
    }

    const hostResourceRecords = utils.toHostResourceRecords(
      ips as Host[],
      this._hostname,
    );

    // Handle host questions first
    const hostQuestionRecords = packet.questions.filter((question) => question.type === QType.A || question.type === QType.AAAA || question.type === QType.ANY);
    for (const question of hostQuestionRecords) {
      const foundHostRecords = hostResourceRecords.filter((record) =>
        record.name === question.name && (record.type === question.type as number || question.type === QType.ANY)
      )
      if (question.type !== QType.ANY) {
        const additionalHostRecords = hostResourceRecords.filter((record) =>
          record.name === question.name && (record.type === (question.type === QType.A ? RType.AAAA : RType.A))
        );
        additionalResourceRecords.push(...additionalHostRecords);
      }
      hasHostRecordsBeenProcessed = true;
      answerResourceRecords.push(...foundHostRecords);
    }

    const answerResourceRecordRowIs = this.localRecordCache.where(packet.questions);
    for (const answerResourceRecordRowI of answerResourceRecordRowIs) {
      processedRowIs.add(answerResourceRecordRowI);
    }
    answerResourceRecords.push(...this.localRecordCache.get(answerResourceRecordRowIs));

    for (const answerResourceRecord of answerResourceRecords) {
      // RFC 6763 12.1. Additionals in PTR
      if (answerResourceRecord.type === RType.PTR) {
        additionalQuestionRecords.push(
          {
            name: answerResourceRecord.data,
            class: QClass.IN,
            type: QType.SRV,
            unicast: false
          },
          {
            name: answerResourceRecord.data,
            class: QClass.IN,
            type: QType.TXT,
            unicast: false
          }
        );
        if (!hasHostRecordsBeenProcessed) {
          hasHostRecordsBeenProcessed = true;
          additionalResourceRecords.push(...hostResourceRecords);
        }
      }
      // RFC 6763 12.2. Additionals in PTR
      else if (answerResourceRecord.type === RType.SRV && !hasHostRecordsBeenProcessed) {
        hasHostRecordsBeenProcessed = true;
        additionalResourceRecords.push(...hostResourceRecords);
      }
    }

    const additionalQuestionRecordRowIs = this.localRecordCache.where(additionalQuestionRecords);
    for (const additionalQuestionRecordRowI of additionalQuestionRecordRowIs) {
      if (!processedRowIs.has(additionalQuestionRecordRowI)) {
        processedRowIs.add(additionalQuestionRecordRowI);
        additionalResourceRecords.push(...this.localRecordCache.get([additionalQuestionRecordRowI]));
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
      additionals: additionalResourceRecords,
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
    const cachableResourceRecords = resourceRecords.filter(
      isCachableResourceRecord,
    );

    // Records with flush bit set will replace a set of records with 1 singular record
    const flushedResourceRecords = cachableResourceRecords.filter(
      (record) => record.flush,
    );
    this.networkRecordCache.delete(flushedResourceRecords);

    // Then set the new records. This order is crucial as to make sure that we don't delete any of the records we are newly setting.
    this.networkRecordCache.set(cachableResourceRecords);

    // We parse the resource records to figure out what service fdqns have been dirtied
    const dirtiedServiceFdqns: Hostname[] = [];
    for (const resourceRecord of resourceRecords) {
      if (
        resourceRecord.type === RType.SRV ||
        resourceRecord.type === RType.TXT
      ) {
        dirtiedServiceFdqns.push(resourceRecord.name as Hostname);
      } else if (
        resourceRecord.type === RType.PTR &&
        resourceRecord.name !== '_services._dns-sd._udp.local'
      ) {
        dirtiedServiceFdqns.push(resourceRecord.data as Hostname);
      } else if (
        resourceRecord.type === RType.A ||
        resourceRecord.type === RType.AAAA
      ) {
        const relatedResourceRecords =
          this.networkRecordCache.getHostnameRelatedResourceRecords(
            resourceRecord.name as Hostname,
          );
        for (const relatedResourceRecord of relatedResourceRecords) {
          if (relatedResourceRecord.type === RType.SRV) {
            dirtiedServiceFdqns.push(relatedResourceRecord.name as Hostname);
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
      let responseRecords = this.networkRecordCache.whereGet([
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
      responseRecords = this.networkRecordCache.whereGet([
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
  private async processExpiredResourceRecords(
    resourceRecord: CachableResourceRecord,
  ) {
    const dirtiedServiceFdqns: Hostname[] = [];

    // Processing record to find related fdqns
    if (
      resourceRecord.type === RType.SRV ||
      resourceRecord.type === RType.TXT
    ) {
      dirtiedServiceFdqns.push(resourceRecord.name as Hostname);
    } else if (
      resourceRecord.type === RType.PTR &&
      resourceRecord.name !== '_services._dns-sd._udp.local'
    ) {
      dirtiedServiceFdqns.push(resourceRecord.data as Hostname);
    } else if (
      resourceRecord.type === RType.A ||
      resourceRecord.type === RType.AAAA
    ) {
      const relatedResourceRecords =
        this.networkRecordCache.getHostnameRelatedResourceRecords(
          resourceRecord.name as Hostname,
        );
      for (const relatedResourceRecord of relatedResourceRecords) {
        if (relatedResourceRecord.type === RType.SRV) {
          dirtiedServiceFdqns.push(relatedResourceRecord.name as Hostname);
        }
      }
    }

    for (const dirtiedServiceFdqn of dirtiedServiceFdqns) {
      const foundService = this.networkServices.get(dirtiedServiceFdqn);
      if (foundService == null) continue;
      this.dispatchEvent(new MDNSServiceRemovedEvent({ detail: foundService }));
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
      this.localServices,
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

  // The most important method, this is used to register a service. All platforms support service registration of some kind. Note that some platforms may resolve service name conflicts automatically. This will have to be dealt with later. The service handle has a method that is able to then later unregister the service.
  public registerService(serviceOptions: ServiceOptions) {
    const service: Service = {
      hostname: this._hostname,
      hosts: [],
      ...serviceOptions,
    };
    const serviceDomain =
      `_${service.type}._${service.protocol}.local` as Hostname;
    const fdqn = `${service.name}.${serviceDomain}` as Hostname;

    this.localServices.set(fdqn, service);
    this.localRecordCacheDirty = true;
    const advertisePacket: Packet = {
      id: 0,
      flags: {
        opcode: PacketOpCode.QUERY,
        rcode: RCode.NoError,
        type: PacketType.RESPONSE,
      },
      questions: [],
      answers: utils.toServiceResourceRecords([service], this._hostname, false),
      additionals: [],
      authorities: [],
    };
    this.advertise(advertisePacket, fdqn);
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
    const serviceDomain = `_${type}._${protocol}.local` as Hostname;
    const fdqn = `${name}.${serviceDomain}` as Hostname;

    const foundService = this.localServices.get(fdqn);
    if (foundService == null) return;

    this.localServices.delete(fdqn);
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
        [foundService],
        this._hostname,
        false,
        0,
      ),
      additionals: [],
      authorities: [],
    };
    this.advertise(advertisePacket, fdqn);
  }

  // Query for all services of a type and protocol, the results will be emitted to eventtarget of the instance of this class.
  public startQuery({
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

    let timer: Timer | undefined;
    let delayMilis = minDelay * 1000;
    const maxDelayMilis = maxDelay * 1000;

    const abortController = new AbortController();
    abortController.signal.addEventListener('abort', () => {
      timer?.cancel();
      this.queries.delete(serviceDomain);
    });

    const promise = new PromiseCancellable<void>(async (_resolve, reject) => {
      const rejectP = () => {
        reject();
        this.queries.delete(serviceDomain);
      };
      await this.sendPacket(queryPacket).catch(rejectP);
      const setTimer = () => {
        timer = new Timer(() => {
          this.sendPacket(queryPacket).catch(rejectP);
          setTimer();
        }, delayMilis);
        delayMilis *= 2;
        if (delayMilis > maxDelayMilis) delayMilis = maxDelayMilis;
      };
      setTimer();
    }, abortController);

    this.queries.set(serviceDomain, promise);
  }

  public stopQuery({
    type,
    protocol,
  }: {
    type: string;
    protocol: 'udp' | 'tcp';
  }) {
    const serviceDomain = `_${type}._${protocol}.local`;
    this.queries.get(serviceDomain)?.cancel();
  }
}

export default MDNS;
