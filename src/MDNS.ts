import type {
  Host,
  Hostname,
  Port,
  Service,
  NetworkInterfaces,
  SocketInfo,
  MulticastSocketInfo,
  SocketHostRow,
  RemoteInfo,
} from './types';
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
  protected getNetworkInterfaces: () =>
    | NetworkInterfaces
    | PromiseLike<NetworkInterfaces>;

  protected localRecordCache: ResourceRecordCache;
  protected localRecordCacheDirty = true;
  protected localServices: Map<Hostname, Service> = new Map();

  protected networkRecordCache: ResourceRecordCache;
  protected networkServices: Map<Hostname, Service> = new Map();
  protected sockets: Array<dgram.Socket> = [];
  protected socketMap: WeakMap<dgram.Socket, SocketInfo> = new WeakMap();
  protected socketHostTable: Table<SocketHostRow> = new Table(
    ['networkInterfaceName', 'address', 'family'],
    [['networkInterfaceName'], ['address']],
  );
  protected _port: Port;
  protected _groups: Array<Host>;
  protected _hostname: Hostname;
  protected _unicast: boolean = false;
  protected _id: number = 0;

  protected queries: Map<string, PromiseCancellable<void>> = new Map();
  protected advertisements: Map<string, PromiseCancellable<void>> = new Map();

  public constructor({
    getNetworkInterfaces = utils.getNetworkInterfaces,
    logger,
  }: {
    getNetworkInterfaces?: () =>
      | NetworkInterfaces
      | PromiseLike<NetworkInterfaces>;
    logger?: Logger;
  } = {}) {
    super();
    this.logger = logger ?? new Logger(this.constructor.name);
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
   * Gets the multicast groups MDNS is bound to.
   * There will always be at least 1 value.
   */
  @ready(new errors.ErrorMDNSNotRunning())
  public get groups(): ReadonlyArray<Host> {
    return this._groups;
  }

  /**
   * Gets the multicast hostname this socket is bound to.
   * This will always end in `.local`.
   */
  @ready(new errors.ErrorMDNSNotRunning())
  public get hostname(): string {
    return this._hostname;
  }

  /**
   * Gets the unicast flag.
   * This will be true if a socket is deemed able to receive unicast responses.
   */
  @ready(new errors.ErrorMDNSNotRunning())
  public get unicast(): string {
    return this._hostname;
  }

  /**
   * Starts MDNS
   * @param opts
   * @param opts.port - The port to bind to. Defaults to 5353 the default MDNS port. Defaults to 5353.
   * @param opts.ipv6Only - Makes MDNS to bind exclusively IPv6 sockets. Defaults to false.
   * @param opts.groups - The multicast group IP addresses to multi-cast on. This must as least have one element. This can have both IPv4 and IPv6 and must. Defaults to `['224.0.0.251', 'ff02::fb']`.
   * @param opts.hostname - The hostname to use for the MDNS stack. Defaults to the OS hostname.
   * @param opts.advertise - Allows MDNS to advertise it's hostnames. Defaults to true.
   * @param opts.id - The unique unsigned 16 bit integer ID used for all outgoing MDNS packets. Defaults to a random number.
   * @throws {RangeError} - If `opts.groups` is empty.
   * @throws {ErrorMDNSSocketInvalidBindAddress} - If a socket cannot bind.
   * @throws {ErrorMDNSInterfaceRange} - If no valid interfaces have been found.
   */
  public async start({
    port = 5353 as Port,
    ipv6Only = false,
    groups = ['224.0.0.251', 'ff02::fb'] as Array<Host>,
    hostname = utils.getHostname(),
    advertise = true,
    id = utils.getRandomPacketId(),
  }: {
    port?: Port;
    ipv6Only?: boolean;

    groups?: Array<Host>;
    hostname?: string;
    advertise?: boolean;
    id?: number;
  }): Promise<void> {
    if (groups.length < 1) {
      throw new RangeError('Must have at least 1 multicast group');
    }

    const sockets: Array<dgram.Socket> = [];
    const platform = utils.getPlatform();
    const multicastTTL = 255;
    // MDNS requires all hostnames to have a `.local` with it
    hostname = (hostname + '.local') as Hostname;
    // DNS Packet ID must be a 16 bit unsigned integer
    id = id & 0xffff;

    let unicast = false;

    let unicastSocket = dgram.createSocket({
      type: 'udp6',
      reuseAddr: false,
      ipv6Only,
    });
    let unicastSocketClose;
    try {
      unicastSocketClose = (await utils.bindSocket(unicastSocket, port, '::'))
        .close;
      unicast = true;
    } catch (e) {
      unicast = false;
    } finally {
      if (unicastSocketClose != null) {
        await unicastSocketClose();
      }
    }

    if (unicast) {
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
          this.handleSocketMessage(msg, rinfo as RemoteInfo, unicastSocket),
        );
        unicastSocket.addListener('error', (err) =>
          this.handleSocketError(err, unicastSocket),
        );
      } catch (e) {
        await unicastSocketClose();
        unicast = false;
      }
    }

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
        const { address, family, netmask } = networkAddress;
        if (ipv6Only) {
          if (family !== 'IPv6') continue;
          socketHosts.push([
            address,
            'udp6',
            networkInterfaceName,
            networkAddress.scopeid,
          ]);
        } else {
          socketHosts.push([
            address,
            family === 'IPv4' ? 'udp4' : 'udp6',
            networkInterfaceName,
            family === 'IPv6' ? networkAddress.scopeid : undefined,
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
              scopeid: networkAddress.scopeid,
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
          platform === 'linux' ? linkLocalGroup : undefined,
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
          // Possible binding failure due to EINVAL.
          // EINVAL due to an invalid multicast group address.
          throw new errors.ErrorMDNSSocketInvalidBindAddress(
            `Could not bind socket with multicast group ${linkLocalGroup}:${port}`,
            {
              cause: e,
            },
          );
        }
        socket.removeListener('error', rejectErrorP);

        socket.addListener('message', (msg, rinfo) =>
          this.handleSocketMessage(msg, rinfo as RemoteInfo, socket),
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
    this._unicast = unicast;
    this._id = id;
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
      );
      const hostResourceRecords = utils.toHostResourceRecords(
        addresses,
        this._hostname,
      );
      const advertisePacket: Packet = {
        id: this._id,
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
      this.advertise(advertisePacket, socketInfo.host, socketInfo);
    }

    // We have to figure out 1 socket at a time
    // And we have to decide what we are doing here
  }

  protected advertise(
    packet: Packet,
    advertisementKey: string,
    socket?: MulticastSocketInfo | Array<MulticastSocketInfo>,
  ) {
    const advertisement = this.advertisements.get(advertisementKey);
    if (advertisement != null) {
      advertisement.cancel();
    }

    const promise = new PromiseCancellable<void>(
      async (resolve, reject, signal) => {
        const rejectFn = (reason: any) => {
          this.advertisements.delete(advertisementKey);
          reject(reason);
        };
        const timer = new Timer(async () => {
          await this.sendMulticastPacket(packet, socket).catch(rejectFn);
          resolve();
        }, 1000);
        signal.addEventListener('abort', () => {
          timer.cancel('abort');
          this.advertisements.delete(advertisementKey);
        });
        await this.sendMulticastPacket(packet, socket).catch(rejectFn);
      },
    );

    this.advertisements.set(advertisementKey, promise);
  }

  /**
   * If the socket is not provided, the message will be sent to all multicast sockets.
   */
  protected async sendMulticastPacket(
    packet: Packet,
    sockets?: MulticastSocketInfo | Array<MulticastSocketInfo>,
  ) {
    if (sockets == null) {
      const unicastSocketInfo = this.sockets.flatMap((s) => {
        const socketInfo = this.socketMap.get(s);
        if (socketInfo == null || socketInfo.unicast) return [];
        return socketInfo;
      });
      return this.sendMulticastPacket(packet, unicastSocketInfo);
    } else if (!Array.isArray(sockets)) {
      return this.sendMulticastPacket(packet, [sockets]);
    }
    for (const socketInfo of sockets) {
      if (socketInfo.unicast) continue;
      await this.sendPacket(packet, socketInfo, socketInfo.group);
    }
  }

  protected async sendPacket(
    packet: Packet,
    sockets: SocketInfo | Array<SocketInfo>,
    address: Host,
  ) {
    if (!Array.isArray(sockets)) {
      return this.sendPacket(packet, [sockets], address);
    }
    const message = generatePacket(packet);
    for (const socketInfo of sockets) {
      try {
        await socketInfo.send(message, this._port, address);
      } catch (e) {
        if (e.code === 'ECANCELED') return;
        throw new errors.ErrorMDNSSocketInvalidSendAddress(
          `Could not send packet to ${address}`,
          {
            cause: e,
          },
        );
      }
    }
  }

  protected findSocketHost(addressHost: Host): SocketHostRow | undefined {
    let parsedAddress: IPv4 | IPv6 | undefined;
    let parsedFamily: 'IPv4' | 'IPv6' | undefined;
    let parsedNetworkInterfaceIndex: string | undefined;
    if (utils.isIPv4(addressHost)) {
      parsedAddress = IPv4.fromString(addressHost);
      parsedFamily = 'IPv4';
    } else {
      const [remoteAddress_, remoteNetworkInterfaceName_] = (
        addressHost as string
      ).split('%', 2);
      parsedAddress = IPv6.fromString(remoteAddress_);
      parsedNetworkInterfaceIndex = remoteNetworkInterfaceName_;
      parsedFamily = 'IPv6';
    }
    for (const [_rowI, socketHost] of this.socketHostTable) {
      if (parsedFamily !== socketHost.family) continue;
      const localAddress = socketHost.parsedAddress;
      const mask = socketHost.parsedMask;
      if (
        (mask.value & parsedAddress.value) !==
        (mask.value & localAddress.value)
      ) {
        continue;
      } else if (
        parsedNetworkInterfaceIndex != null &&
        (parsedNetworkInterfaceIndex !== socketHost.networkInterfaceName ||
          parseInt(parsedNetworkInterfaceIndex) !== (socketHost as any).scopeid)
      ) {
        continue;
      }
      return socketHost;
    }
  }

  protected async handleSocketMessage(
    msg: Buffer,
    rinfo: RemoteInfo,
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

    let packet: Packet;
    try {
      packet = parsePacket(msg);
    } catch (err) {
      return;
    }
    if (packet.id === this._id) return;
    if (packet.flags.type === PacketType.QUERY) {
      await this.handleSocketMessageQuery(packet, rinfo, socket);
    } else {
      await this.handleSocketMessageResponse(packet, rinfo, socket);
    }
  }

  protected async handleSocketMessageQuery(
    packet: Packet,
    rinfo: RemoteInfo,
    socket: dgram.Socket,
  ) {
    const socketInfo = this.socketMap.get(socket);
    if (socketInfo == null) return;
    if (packet.flags.type !== PacketType.QUERY) return;
    const answerResourceRecords: ResourceRecord[] = [];
    const additionalResourceRecords: ResourceRecord[] = [];
    const additionalQuestionRecords: QuestionRecord[] = [];
    const processedRowIs = new Set<number>();
    let hasHostRecordsBeenProcessed = false;
    let canResponseBeUnicast = false;

    let networkInterfaceName: string | undefined;

    if (socketInfo.unicast) {
      networkInterfaceName = this.findSocketHost(
        rinfo.address,
      )?.networkInterfaceName;
    } else {
      networkInterfaceName = socketInfo?.networkInterfaceName;
    }

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
      ips,
      this._hostname,
    );

    // Handle host questions first
    for (const question of packet.questions) {
      if (question.unicast) {
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
      id: this._id,
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
    // If a query was received through unicast, we respond through unicast, otherwise we respond through multicast
    if (canResponseBeUnicast ?? socketInfo.unicast) {
      await this.sendPacket(responsePacket, socketInfo, rinfo.address);
    } else {
      await this.sendMulticastPacket(responsePacket, socketInfo);
    }
  }

  protected async handleSocketMessageResponse(
    packet: Packet,
    rinfo: RemoteInfo,
    socket: dgram.Socket,
  ) {
    await this.processIncomingResourceRecords(
      packet.answers.concat(packet.additionals),
      rinfo,
      socket,
    );
  }

  protected async processIncomingResourceRecords(
    resourceRecords: ResourceRecord[],
    rinfo: RemoteInfo,
    socket: dgram.Socket,
  ) {
    const socketInfo = this.socketMap.get(socket);
    if (socketInfo == null) return;
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
        unicast: this._unicast,
      });
      remainingQuestions.set(QType.SRV, {
        name: dirtiedServiceFdqn,
        type: QType.SRV,
        class: QClass.IN,
        unicast: this._unicast,
      });
      let responseRecords = this.networkRecordCache.whereGet([
        ...remainingQuestions.values(),
      ]);
      for (const responseRecord of responseRecords) {
        remainingQuestions.delete(responseRecord.type as number);
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
        unicast: this._unicast,
      });
      remainingQuestions.set(QType.AAAA, {
        name: partialService.hostname,
        type: QType.AAAA,
        class: QClass.IN,
        unicast: this._unicast,
      });
      responseRecords = this.networkRecordCache.whereGet([
        ...remainingQuestions.values(),
      ]);
      for (const responseRecord of responseRecords) {
        remainingQuestions.delete(responseRecord.type as number);
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
      const packet: Packet = {
        id: this._id,
        flags: {
          opcode: PacketOpCode.QUERY,
          rcode: RCode.NoError,
          type: PacketType.QUERY,
        },
        questions: allRemainingQuestions,
        answers: [],
        additionals: [],
        authorities: [],
      };
      // TODO: put dgram.Socket onto the socketHostMap
      // when a unicast response is received, we make sure to only send a multicast query back on the interface that received the unicast response.
      if (socketInfo.unicast) {
        const socketHost = this.findSocketHost(rinfo.address);
        if (socketHost != null) {
          for (const socket of this.sockets) {
            const senderSocketInfo = this.socketMap.get(socket);
            if (
              senderSocketInfo == null ||
              senderSocketInfo.unicast ||
              senderSocketInfo.host !== socketHost.address
            ) {
              continue;
            }
            await this.sendMulticastPacket(packet, senderSocketInfo);
            return;
          }
        }
      }
      await this.sendMulticastPacket(
        packet,
        !socketInfo.unicast ? socketInfo : undefined,
      );
    }
  }

  // We processed expired records here. Note that this also processes records of TTL 0, as they expire after 1 second as per spec.
  protected async processExpiredResourceRecords(
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

  protected extractRelatedFdqns(
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

  protected async handleSocketError(e: any, socket: dgram.Socket) {
    throw new errors.ErrorMDNSSocket(
      `An error occurred on a socket that MDNS has bound to ${
        socket.address().address
      }`,
      {
        cause: e,
      },
    );
  }

  /**
   * Stops MDNS
   * This will unregister all services and hosts, sending a goodbye packet.
   * This will flush all records from the cache.
   * This will close all sockets.
   */
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
      );
      const hostResourceRecords = utils.toHostResourceRecords(
        addresses,
        this._hostname,
        true,
        0,
      );
      const advertisePacket: Packet = {
        id: this._id,
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
      await this.sendMulticastPacket(advertisePacket, socketInfo);
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

  /**
   * Registers a service
   * @param opts
   * @param opts.name - The name of the service you want to register.
   * @param opts.type - The type of service you want to register.
   * @param opts.protocol - The protocol of service you want to register. This is either 'udp' or 'tcp'.
   * @param opts.port - The port of the service you want to register.
   * @param opts.txt - The TXT data of the service you want to register. This is represented as a key-value POJO.
   * @param opts.advertise - Allows MDNS to advertise the service on registration. Defaults to true.
   */
  @ready(new errors.ErrorMDNSNotRunning())
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
      id: this._id,
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

  /**
   * Un-registers a service that you have registered with {@link MDNS.registerService}
   * @param opts
   * @param opts.name - The name of the service you want to unregister.
   * @param opts.type - The type of service you want to unregister.
   * @param opts.protocol - The protocol of service you want to unregister. This is either 'udp' or 'tcp'.
   */
  @ready(new errors.ErrorMDNSNotRunning())
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
      id: this._id,
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

  /**
   * Start a query for services of a specific type and protocol
   * @param opts
   * @param opts.type - The type of service you want to query for.
   * @param opts.protocol - The protocol of service you want to query for. This is either 'udp' or 'tcp'.
   * @param opts.minDelay - The minimum delay between queries in seconds. Defaults to 1.
   * @param opts.maxDelay - The maximum delay between queries in seconds. Defaults to 3600 (1 hour).
   */
  @ready(new errors.ErrorMDNSNotRunning())
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
      unicast: this._unicast,
    };
    const queryPacket: Packet = {
      id: this._id,
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

    const promise = new PromiseCancellable<void>(
      async (_resolve, reject, signal) => {
        const rejectFn = (reason: any) => {
          this.queries.delete(serviceDomain);
          reject(reason);
        };
        let delayMilis = minDelay * 1000;
        const maxDelayMilis = maxDelay * 1000;

        let timer: Timer;

        const setTimer = () => {
          timer = new Timer(async () => {
            await this.sendMulticastPacket(queryPacket).catch(rejectFn);
            setTimer();
          }, delayMilis);
          delayMilis *= 2;
          if (delayMilis > maxDelayMilis) delayMilis = maxDelayMilis;
        };
        setTimer();

        signal.addEventListener('abort', () => {
          timer.cancel('abort');
          this.queries.delete(serviceDomain);
        });

        await this.sendMulticastPacket(queryPacket).catch(rejectFn);
      },
    );

    this.queries.set(serviceDomain, promise);
  }

  /**
   * Stops a service query that you have started with {@link MDNS.startQuery}
   * @param opts
   * @param opts.type - The type of service you want to stop querying for.
   * @param opts.protocol - The protocol of service you want to stop querying for. This is either 'udp' or 'tcp'.
   */
  @ready(new errors.ErrorMDNSNotRunning())
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
