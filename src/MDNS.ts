import type { Host, Hostname, Port, Service, NetworkInterfaces } from './types';
import type { MDNSCacheExpiredEvent } from './cache';
import type {
  CachableResourceRecord,
  Packet,
  QuestionRecord,
  ResourceRecord,
} from './dns';
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
import { socketUtils } from './native';

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

      udpType: 'udp4' | 'udp6';
    } & (
      | {
          unicast: true;
        }
      | {
          unicast?: false;
          networkInterfaceName: string;
          host: Host;
          group: Host;
        }
    )
  > = new WeakMap();
  protected socketHostTable: Table<
    {
      networkInterfaceName: string;
      address: string;
      netmask: string;
    } & (
      | {
          parsedAddress: IPv4;
          parsedMask: IPv4Mask;
          family: 'IPv4';
        }
      | {
          parsedAddress: IPv6;
          parsedMask: IPv6Mask;
          family: 'IPv6';
          scopeid: number;
        }
    )
  > = new Table(
    ['networkInterfaceName', 'address', 'family'],
    [['networkInterfaceName'], ['address']],
  );
  protected _port: Port;
  protected _type: 'ipv4' | 'ipv6' | 'ipv4&ipv6';
  protected _groups: Array<Host>;
  protected _hostname: Hostname;
  protected _unicast: boolean = false;

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
   * @param opts.reuseAddr - Allows MDNS to bind on the same port that an existing MDNS stack is already bound on. Defaults to true.
   */
  public async start({
    port = 5353 as Port,
    ipv6Only = false,
    groups = ['224.0.0.251', 'ff02::fb'] as Array<Host>,
    hostname = utils.getHostname(),
    advertise = true,
  }: {
    port?: Port;
    ipv6Only?: boolean;

    groups?: Array<Host>;
    hostname?: string;
    advertise?: boolean;
  }): Promise<void> {
    if (groups.length < 1) {
      throw new RangeError('Must have at least 1 multicast group');
    }

    const sockets: Array<dgram.Socket> = [];
    const platform = utils.getPlatform();
    const multicastTTL = 255;

    let unicastSocket = dgram.createSocket({
      type: 'udp6',
      reuseAddr: false,
      ipv6Only,
    });
    let unicastSocketClose;
    try {
      unicastSocketClose = (await utils.bindSocket(unicastSocket, port, '::'))
        .close;
      this._unicast = true;
    } catch (e) {
      this._unicast = false;
    } finally {
      if (unicastSocketClose != null) {
        await unicastSocketClose();
      }
    }

    if (this._unicast) {
      unicastSocket = dgram.createSocket({
        type: 'udp6',
        reuseAddr: true,
        ipv6Only,
      });
      try {
        const { send, close } = await utils.bindSocket(
          unicastSocket,
          port,
          '::',
        );
        unicastSocketClose = close;
        if (platform === 'linux') {
          socketUtils.disableSocketMulticastAll(
            (unicastSocket as any)._handle.fd,
          );
        }
        sockets.push(unicastSocket);
        this.socketMap.set(unicastSocket, {
          close,
          send,
          udpType: 'udp6',
          unicast: true,
        });
        unicastSocket.setTTL(multicastTTL);
        unicastSocket.setMulticastTTL(0);
        unicastSocket.setMulticastLoopback(false);
        unicastSocket.addListener('message', (msg, rinfo) =>
          this.handleSocketMessage(msg, rinfo, unicastSocket),
        );
        unicastSocket.addListener('error', (err) =>
          this.handleSocketError(err, unicastSocket),
        );
      } catch (e) {
        await unicastSocketClose();
        this._unicast = false;
      }
    }

    // TODO: move this to where it is exactly needed so `hostname` should be the same property
    // MDNS requires all hostnames to have a `.local` with it
    hostname = (hostname + '.local') as Hostname;

    this.logger.info(`Start ${this.constructor.name}`);

    const socketHosts: Array<[Host, 'udp4' | 'udp6', string, number?]> = [];
    // When binding to wild card
    // We explicitly find out all the interfaces we are going to bind to
    // This is because we only want to respond on the interface where we received
    // A query or announcement from
    // This is because each network could have its own multicast group
    // And if a query is received on one network's multicast group
    // Then we want to send that back on the same network
    // Using the same interface, so a specific socket
    const networkInterfaces = await this.getNetworkInterfaces();
    for (const networkInterfaceName in networkInterfaces) {
      const networkAddresses = networkInterfaces[networkInterfaceName];
      if (networkAddresses == null) continue;
      for (const networkAddress of networkAddresses) {
        if (networkAddress.internal) continue;
        const { address, family, netmask, scopeid } = networkAddress;
        if (ipv6Only) {
          if (family !== 'IPv6') continue;
          socketHosts.push([
            address as Host,
            'udp6',
            networkInterfaceName,
            scopeid,
          ]);
        } else {
          socketHosts.push([
            address as Host,
            family === 'IPv4' ? 'udp4' : 'udp6',
            networkInterfaceName,
            scopeid,
          ]);
        }
        try {
          if (networkAddress.family === 'IPv4') {
            this.socketHostTable.insertRow({
              ...networkAddress,
              family: 'IPv4',
              networkInterfaceName,
              parsedAddress: IPv4.fromString(address),
              parsedMask: new IPv4Mask(netmask),
            });
          } else {
            this.socketHostTable.insertRow({
              ...networkAddress,
              family: 'IPv6',
              networkInterfaceName,
              parsedAddress: IPv6.fromString(address),
              parsedMask: new IPv6Mask(netmask),
              scopeid: networkAddress.scopeid as number,
            });
          }
        } catch (err) {
          this.logger.warn(
            `Parsing network interface address failed: ${address}`,
          );
        }
      }
    }
    if (socketHosts.length < 1) {
      // TODO: replace this with domain specific error
      throw new errors.ErrorMDNSInterfaceRange(
        'MDNS could not resolve any valid network interfaces',
      );
    }

    // Here we create multiple sockets
    // This may only contain 1
    // or we end up with multiple sockets we are working with
    for (const [socketHost, udpType, networkInterfaceName, scopeid] of [
      ...socketHosts,
    ]) {
      const linkLocalInterfaceIndex =
        platform !== 'win32' ? networkInterfaceName : scopeid;
      const linkLocalSocketHost =
        udpType === 'udp6' && socketHost.startsWith('fe80')
          ? ((socketHost + '%' + linkLocalInterfaceIndex) as Host)
          : socketHost;

      for (const group of [...groups]) {
        if (utils.isIPv4(group) && udpType !== 'udp4') continue;
        if (utils.isIPv6(group) && udpType !== 'udp6') continue;
        const linkLocalGroup =
          udpType === 'udp6' && group.startsWith('ff02')
            ? ((group + '%' + linkLocalInterfaceIndex) as Host)
            : group;
        const socket = dgram.createSocket({
          type: udpType,
          reuseAddr: true,
          ipv6Only,
        });
        const socketBind = utils.promisify(socket.bind).bind(socket);
        const socketClose = utils.promisify(socket.close).bind(socket);
        const socketSend = utils.promisify(socket.send).bind(socket);
        const { p: errorP, rejectP: rejectErrorP } = utils.promise();
        socket.once('error', rejectErrorP);
        const socketBindP = socketBind(
          port,
          platform !== 'win32' ? linkLocalSocketHost : undefined,
        );
        try {
          await Promise.race([socketBindP, errorP]);
          if (platform === 'linux') {
            socketUtils.disableSocketMulticastAll((socket as any)._handle.fd);
          }
          socket.setMulticastInterface(linkLocalSocketHost);
          socket.addMembership(linkLocalGroup, linkLocalSocketHost);
          socket.setMulticastTTL(multicastTTL);
          socket.setTTL(multicastTTL);
          socket.setMulticastLoopback(true);
        } catch (e) {
          for (const socket of sockets.reverse()) {
            socket.close();
          }
          // TODO: edit comment
          // Possible binding failure due to EINVAL or ENOTFOUND.
          // EINVAL due to using IPv4 address where udp6 is specified.
          // ENOTFOUND when the hostname doesn't resolve, or doesn't resolve to IPv6 if udp6 is specified
          // or doesn't resolve to IPv4 if udp4 is specified.
          throw new errors.ErrorMDNSSocketInvalidBindAddress(
            `Could not bind socket to ${linkLocalGroup}`,
            {
              cause: e,
            },
          );
        }
        socket.removeListener('error', rejectErrorP);

        socket.addListener('message', (msg, rinfo) =>
          this.handleSocketMessage(msg, rinfo, socket),
        );
        socket.addListener('error', (err) =>
          this.handleSocketError(err, socket),
        );

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
    this._port = port;
    this._groups = groups;
    this._hostname = hostname as Hostname;
    this.localRecordCache = await ResourceRecordCache.createResourceRecordCache(
      { timerDisabled: true },
    );
    this.networkRecordCache =
      await ResourceRecordCache.createResourceRecordCache();
    this.networkRecordCache.addEventListener(
      'expired',
      (event: MDNSCacheExpiredEvent) =>
        this.processExpiredResourceRecords(event.detail),
    );

    if (!advertise) return;

    for (const socket of this.sockets) {
      const socketInfo = this.socketMap.get(socket);
      if (socketInfo == null || socketInfo.unicast) continue;
      const hostRowIs = this.socketHostTable.whereRows(
        ['networkInterfaceName'],
        [socketInfo?.networkInterfaceName],
      );
      const addresses = hostRowIs.flatMap(
        (rowI) => this.socketHostTable.getRow(rowI)?.address ?? [],
      ) as Host[];
      const hostResourceRecords = utils.toHostResourceRecords(
        addresses,
        this._hostname,
      );
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
      const rejectP = () => {
        this.advertisements.delete(advertisementKey);
        reject();
      };
      await this.sendPacket(packet, socket).catch(rejectP);
      timer = new Timer(async () => {
        await this.sendPacket(packet, socket).catch(rejectP);
        resolve();
      }, 1000);
    }, abortController);

    this.advertisements.set(advertisementKey, promise);
  }

  /**
   * If the socket is not provided, the message will be sent to all multicast sockets.
   */
  private async sendPacket(
    packet: Packet,
    socket?: dgram.Socket,
    address?: Host,
  ) {
    const message = generatePacket(packet);
    let sockets: dgram.Socket[];
    if (socket == null) {
      sockets = this.sockets.filter(
        (s) => this.socketMap.get(s)?.unicast !== true,
      );
    } else {
      sockets = [socket];
    }
    for (const socket of sockets) {
      const socketInfo = this.socketMap.get(socket);
      let sendAddress: Host | undefined;
      if (socketInfo?.unicast) {
        if (address == null) {
          throw new errors.ErrorMDNSSocketInvalidSendAddress(
            `No send address provided for unicast socket`,
          );
        }
        sendAddress = address;
      } else {
        sendAddress = address ?? socketInfo?.group;
      }
      try {
        await socketInfo?.send(message, this._port, sendAddress);
      } catch (e) {
        if (e.code === "ECANCELED") return;
        throw new errors.ErrorMDNSSocketInvalidSendAddress(
          `Could not send packet to ${sendAddress}`,
          {
            cause: e,
          },
        );
      }
    }
  }

  private async handleSocketMessage(
    msg: Buffer,
    rinfo: dgram.RemoteInfo,
    socket: dgram.Socket,
  ) {
    const socketInfo = this.socketMap.get(socket);
    if (!socketInfo?.unicast) {
      // We check if the received message is from the same subnet in order to determine if we should respond.
      try {
        const addressRowI = this.socketHostTable
          .whereRows(['address'], [socketInfo?.host])
          .at(0);
        const address = addressRowI
          ? this.socketHostTable.getRow(addressRowI)
          : undefined;
        if (address != null) {
          const mask = address.parsedMask;
          const localAddress = address.parsedAddress;
          let remoteAddress: IPv4 | IPv6;
          let remoteNetworkInterfaceIndex: string | undefined;
          if (address.family === 'IPv4') {
            remoteAddress = IPv4.fromString(rinfo.address);
            if (
              (mask.value & remoteAddress.value) !==
              (mask.value & localAddress.value)
            ) {
              return;
            }
          } else {
            const [remoteAddress_, remoteNetworkInterfaceName_] =
              rinfo.address.split('%', 2);
            remoteAddress = IPv6.fromString(remoteAddress_);
            remoteNetworkInterfaceIndex = remoteNetworkInterfaceName_;
          }
          if (
            (mask.value & remoteAddress.value) !==
            (mask.value & localAddress.value)
          ) {
            return;
          } else if (
            remoteNetworkInterfaceIndex != null &&
            (remoteNetworkInterfaceIndex !== address.networkInterfaceName ||
              parseInt(remoteNetworkInterfaceIndex) !==
                (address as any).scopeid)
          ) {
            return;
          }
        }
      } catch (_err) {
        this.logger.warn(`Parsing remote address failed: ${rinfo.address}`);
      }
    }

    let packet: Packet | undefined;
    try {
      packet = parsePacket(msg);
    } catch (err) {}
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
    const socketInfo = this.socketMap.get(socket);
    if (socketInfo?.unicast) return;
    if (packet.flags.type !== PacketType.QUERY) return;
    const answerResourceRecords: ResourceRecord[] = [];
    const additionalResourceRecords: ResourceRecord[] = [];
    const additionalQuestionRecords: QuestionRecord[] = [];
    const processedRowIs = new Set<number>();
    let hasHostRecordsBeenProcessed = false;
    let canResponseBeUnicast = false;

    const networkInterfaceName = socketInfo?.networkInterfaceName;

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
        ) as CachableResourceRecord[],
      );
    }

    const hostResourceRecords = utils.toHostResourceRecords(
      ips as Host[],
      this._hostname,
    );

    // Handle host questions first
    for (const question of packet.questions) {
      if (question.unicast && this._unicast) {
        canResponseBeUnicast = true;
      }
      if (
        (question.type === QType.A ||
          question.type === QType.AAAA ||
          question.type === QType.ANY) &&
        !hasHostRecordsBeenProcessed
      ) {
        const foundHostRecords = hostResourceRecords.filter(
          (record) =>
            record.name === question.name &&
            (record.type === (question.type as number) ||
              question.type === QType.ANY),
        );
        if (question.type !== QType.ANY) {
          const additionalHostRecords = hostResourceRecords.filter(
            (record) =>
              record.name === question.name &&
              record.type ===
                (question.type === QType.A ? RType.AAAA : RType.A),
          );
          additionalResourceRecords.push(...additionalHostRecords);
        }
        hasHostRecordsBeenProcessed = true;
        answerResourceRecords.push(...foundHostRecords);
      }
    }

    const answerResourceRecordRowIs = this.localRecordCache.where(
      packet.questions,
    );
    for (const answerResourceRecordRowI of answerResourceRecordRowIs) {
      processedRowIs.add(answerResourceRecordRowI);
    }
    answerResourceRecords.push(
      ...this.localRecordCache.get(answerResourceRecordRowIs),
    );

    for (const answerResourceRecord of answerResourceRecords) {
      // RFC 6763 12.1. Additionals in PTR
      if (answerResourceRecord.type === RType.PTR) {
        additionalQuestionRecords.push(
          {
            name: answerResourceRecord.data,
            class: QClass.IN,
            type: QType.SRV,
          },
          {
            name: answerResourceRecord.data,
            class: QClass.IN,
            type: QType.TXT,
          },
        );
        if (!hasHostRecordsBeenProcessed) {
          hasHostRecordsBeenProcessed = true;
          additionalResourceRecords.push(...hostResourceRecords);
        }
      }
      // RFC 6763 12.2. Additionals in PTR
      else if (
        answerResourceRecord.type === RType.SRV &&
        !hasHostRecordsBeenProcessed
      ) {
        hasHostRecordsBeenProcessed = true;
        additionalResourceRecords.push(...hostResourceRecords);
      }
    }

    // Iterate over the found additional records. If it has already been processed, we do not add it to the additional records, this is done so that we can avoid duplicate records in the answer and additional sections.
    const additionalQuestionRecordRowIs = this.localRecordCache.where(
      additionalQuestionRecords,
    );
    for (const additionalQuestionRecordRowI of additionalQuestionRecordRowIs) {
      if (!processedRowIs.has(additionalQuestionRecordRowI)) {
        processedRowIs.add(additionalQuestionRecordRowI);
        additionalResourceRecords.push(
          ...this.localRecordCache.get([additionalQuestionRecordRowI]),
        );
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
    await this.sendPacket(
      responsePacket,
      socket,
      canResponseBeUnicast ? (rinfo.address as Host) : undefined,
    );
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
    const dirtiedServiceFdqns = this.extractRelatedFdqns(resourceRecords);

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
          partialService.port = responseRecord.data.port as Port;
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
    const dirtiedServiceFdqns = this.extractRelatedFdqns(resourceRecord);

    for (const dirtiedServiceFdqn of dirtiedServiceFdqns) {
      const foundService = this.networkServices.get(dirtiedServiceFdqn);
      if (foundService == null) continue;
      this.dispatchEvent(new MDNSServiceRemovedEvent({ detail: foundService }));
      this.networkServices.delete(dirtiedServiceFdqn);
    }
  }

  private extractRelatedFdqns(
    resourceRecords: ResourceRecord | Array<ResourceRecord>,
  ): Array<Hostname> {
    if (!Array.isArray(resourceRecords)) {
      return this.extractRelatedFdqns([resourceRecords]);
    }
    const relatedFdqns: Array<Hostname> = [];
    for (const resourceRecord of resourceRecords) {
      if (
        resourceRecord.type === RType.SRV ||
        resourceRecord.type === RType.TXT
      ) {
        relatedFdqns.push(resourceRecord.name as Hostname);
      } else if (
        resourceRecord.type === RType.PTR &&
        resourceRecord.name !== '_services._dns-sd._udp.local'
      ) {
        relatedFdqns.push(resourceRecord.data as Hostname);
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
            relatedFdqns.push(relatedResourceRecord.name as Hostname);
          }
        }
      }
    }
    return relatedFdqns;
  }

  private async handleSocketError(e: any, socket: dgram.Socket) {
    throw new errors.ErrorMDNSSocket(
      `An error occurred on a socket that MDNS has bound to ${
        socket.address().address
      }`,
      {
        cause: e,
      },
    );
  }

  // Unregister all services, hosts, and sockets. For platforms with a built-in mDNS responder, this will not actually stop the responder.
  public async stop(): Promise<void> {
    // Cancel Queries and Advertisements
    for (const query of this.queries.values()) {
      query.cancel();
    }
    for (const advertisement of this.advertisements.values()) {
      advertisement.cancel();
    }

    // Send the goodbye packet
    const serviceResourceRecords = utils.toServiceResourceRecords(
      [...this.localServices.values()],
      this._hostname,
      false,
      0,
    );
    for (const socket of this.sockets) {
      const socketInfo = this.socketMap.get(socket);
      if (socketInfo == null || socketInfo.unicast) continue;
      const hostRowIs = this.socketHostTable.whereRows(
        ['networkInterfaceName'],
        [socketInfo?.networkInterfaceName],
      );
      const addresses = hostRowIs.flatMap(
        (rowI) => this.socketHostTable.getRow(rowI)?.address ?? [],
      ) as Host[];
      const hostResourceRecords = utils.toHostResourceRecords(
        addresses,
        this._hostname,
        true,
        0,
      );
      const advertisePacket: Packet = {
        id: 0,
        flags: {
          opcode: PacketOpCode.QUERY,
          rcode: RCode.NoError,
          type: PacketType.RESPONSE,
        },
        questions: [],
        answers: serviceResourceRecords.concat(hostResourceRecords),
        additionals: [],
        authorities: [],
      };
        await this.sendPacket(advertisePacket, socket);
      }

    // Clear Services and Cache
    await this.localRecordCache.destroy();
    this.localRecordCacheDirty = true;
    this.localServices.clear();
    await this.networkRecordCache.destroy();
    this.networkServices.clear();

    // Close all Sockets
    for (const socket of this.sockets) {
      const socketInfo = this.socketMap.get(socket);
      await socketInfo?.close();
      this.socketMap.delete(socket);
    }
    this.socketHostTable.clearTable();
    this.sockets = [];
  }

  public registerService({
    name,
    type,
    protocol,
    port,
    txt,
    advertise = true,
  }: {
    name: string;
    type: string;
    protocol: 'udp' | 'tcp';
    port: Port;
    txt?: Record<string, string>;
    advertise?: boolean;
  }) {
    const service: Service = {
      name,
      type,
      protocol,
      port,
      txt,
      hostname: this._hostname,
      hosts: [],
    };
    const serviceDomain =
      `_${service.type}._${service.protocol}.local` as Hostname;
    const fdqn = `${service.name}.${serviceDomain}` as Hostname;

    this.localServices.set(fdqn, service);
    this.localRecordCacheDirty = true;

    if (!advertise) return;
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

    const promise = new PromiseCancellable<void>(async (_resolve, reject, signal) => {
      let delayMilis = minDelay * 1000;
      const maxDelayMilis = maxDelay * 1000;
  
      let timer: Timer;
      
      const setTimer = () => {
        timer = new Timer(async () => {
          await this.sendPacket(queryPacket).catch(reject);
          setTimer();
        }, delayMilis);
        delayMilis *= 2;
        if (delayMilis > maxDelayMilis) delayMilis = maxDelayMilis;
      }
      setTimer();

      signal.addEventListener('abort', () => {
        timer.cancel('abort');
        this.queries.delete(serviceDomain);
      });

      await this.sendPacket(queryPacket).catch(reject);
    });

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
