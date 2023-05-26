import type { RemoteInfo } from 'dgram';
import type { NetworkInterfaceInfo } from 'os';
import { Socket } from 'dgram';
import { type } from 'os';
import { createSocket } from 'dgram';
import { networkInterfaces } from 'os';
import { promisify } from 'util';
import { StartStop } from '@matrixai/async-init/dist/StartStop';
import dnsPacket from 'dns-packet';

const MDNS_GROUP_ADDR = '224.0.0.251';
const MDNS_PORT = 5353;
const MDNS_TTL = 255;

// RFC 6762 10. TTLs of various records
const HOSTNAME_RR_TTL = 120;
const OTHER_RR_TTL = 4500;

interface Responder extends StartStop {}
@StartStop()
class Responder extends EventTarget {
  // All the maps here have their keys as an interface's name. The reason for this is we want to be able to tell what interface a DNS packet should be sent from.
  protected ifaces: Map<string, NetworkInterfaceInfo[]>;
  protected ifaceSockets: Map<string, Socket>;
  protected ifaceResourceRecords: Map<string, dnsPacket.Answer[]>;
  protected ifaceServices: Map<string, dnsPacket.Answer[][]>;

  constructor() {
    super();
    this.ifaces = new Map();
    this.ifaceSockets = new Map();
    this.ifaceResourceRecords = new Map();
  }

  public async start(): Promise<void> {
    if (this.ifaces.size === 0) {
      this.scanInterfaces();
    }

    for (const [name, iface] of this.ifaces) {
      // We assume that every network interface only has 1 IPv4 address. This address list should however be a method param so it can be derived from Polykey's bound interfaces.
      const ifaceInfo = iface?.find(
        (iface) => iface.family === 'IPv4' && !iface.internal,
      );
      if (typeof ifaceInfo !== 'undefined') {
        const socket = createSocket({ type: 'udp4', reuseAddr: true });

        socket.addListener('close', () => {
          this.ifaceSockets.delete(name);
        });

        socket.addListener('message', (buffer, rinfo) => {
          try {
            const packet = dnsPacket.decode(buffer);
            if (packet.type === 'query') {
              this.handleQuery(packet, rinfo);
            } else {
            }
          } catch (e) {}
        });

        await promisify(socket.bind).bind(socket)(MDNS_PORT, '0.0.0.0');

        socket.addMembership(MDNS_GROUP_ADDR, ifaceInfo.address);
        socket.setTTL(MDNS_TTL);
        socket.setMulticastTTL(MDNS_TTL);
        socket.setMulticastLoopback(true);

        this.ifaceSockets.set(name, socket);
      }
    }
  }

  public async close(): Promise<void> {
    // Close all sockets and clear the sockets map
    await Promise.all([...this.ifaceSockets.values()].map((e) => e.close()));
    this.ifaceSockets.clear();
    this.ifaces.clear();
  }

  public scanInterfaces() {
    for (const [name, ifaces] of Object.entries(networkInterfaces())) {
      this.ifaces.set(name, ifaces ?? []);
    }
  }

  private async handleQuery(
    packet: dnsPacket.Packet,
    rinfo: RemoteInfo,
  ): Promise<void> {
    console.log(packet, rinfo);
    const answers: Map<string, dnsPacket.Answer[]> = new Map();

    for (const [ifaceName, hostAnswers] of this.ifaceResourceRecords) {
      const foundAnswers = hostAnswers.filter(
        (answer) =>
          packet.questions?.findIndex((question) =>
            question.name === answer.name &&
            question.type === answer.type &&
            typeof question.class === 'undefined'
              ? true
              : (answer as any).class === question.class,
          ) !== -1,
      );
      if (foundAnswers.length > 0) {
        answers.set(ifaceName, foundAnswers);
      }
    }

    const response: dnsPacket.Packet = {
      id: 0,
      type: 'response',
      flags: 1024,
      answers: [...answers.values()].flat(),
    };

    console.log(response, 'response');

    await this.sendPacket(response, [...answers.keys()]);
  }

  private async sendPacket(
    packet: dnsPacket.Packet,
    ifacesOrSockets: (string | NetworkInterfaceInfo | Socket)[],
    address = MDNS_GROUP_ADDR,
  ) {
    const sockets: Socket[] = [];

    // Refactor this later, it's a mess!
    for (const ifaceOrSocket of ifacesOrSockets) {
      if (typeof ifaceOrSocket === 'string') {
        const ifaceName = ifaceOrSocket;
        const socket = this.ifaceSockets.get(ifaceName);
        if (typeof socket !== 'undefined') sockets.push(socket);
      } else if (ifaceOrSocket instanceof Socket) {
        sockets.push(ifaceOrSocket);
      } else {
        const ifaceName = [...this.ifaces.keys()].find((ifaceName) =>
          this.ifaces
            .get(ifaceName)
            ?.findIndex((iface) => iface.address === ifaceOrSocket.address),
        );
        const socket = ifaceName ? this.ifaceSockets.get(ifaceName) : undefined;
        if (typeof socket !== 'undefined') sockets.push(socket);
      }
    }

    await Promise.all(
      sockets.map((socket) =>
        promisify(socket.send).bind(socket)(
          dnsPacket.encode(packet),
          MDNS_PORT,
          address,
        ),
      ),
    );
  }

  public async addHost({
    hostname,
    ifaceName,
    ttl = HOSTNAME_RR_TTL,
  }: {
    hostname: string;
    ifaceName: string;
    ttl?: number;
  }): Promise<dnsPacket.StringAnswer[]> {
    const iface = this.ifaces.get(ifaceName);
    if (typeof iface === 'undefined') throw new Error('Invalid interface');

    const answers: dnsPacket.StringAnswer[] = [];

    const ipv4Address = iface.find((iface) => iface.family === 'IPv4')?.address;
    const ipv6Address = iface.find((iface) => iface.family === 'IPv6')?.address;

    if (typeof ipv4Address !== 'undefined') {
      answers.push({
        name: hostname,
        type: 'A',
        class: 'IN',
        data: ipv4Address,
        ttl,
      });
    }
    if (typeof ipv6Address !== 'undefined') {
      answers.push({
        name: hostname,
        type: 'AAAA',
        class: 'IN',
        data: ipv6Address,
        ttl,
      });
    }

    this.ifaceResourceRecords.set(ifaceName, [
      ...(this.ifaceResourceRecords.get(ifaceName) ?? []),
      ...answers,
    ]);

    return answers;
  }

  public async advertiseService({
    hostname,
    ifaceName,
    serviceType,
    servicePort,
    ttl = HOSTNAME_RR_TTL,
  }: {
    hostname: string;
    ifaceName: string;
    serviceType: string;
    servicePort: number;
    ttl?: number;
  }): Promise<void> {
    const iface = this.ifaces.get(ifaceName);
    if (typeof iface === 'undefined') throw new Error('Invalid interface');

    // Implement probing before this point.

    const localTLD = '.local';

    const fullServiceType = serviceType + localTLD;

    let hostnameDomain = hostname;
    if (hostname.endsWith(localTLD)) {
      hostnameDomain = hostname.slice(0, -localTLD.length);
    } else {
      hostname += localTLD;
    }

    const fqdn = hostnameDomain + '.' + fullServiceType;

    const answers: dnsPacket.Answer[] = [
      {
        name: '_services._dns-sd._udp.local',
        type: 'PTR',
        class: 'IN',
        ttl,
        data: fullServiceType,
      },
      {
        name: fullServiceType,
        type: 'PTR',
        class: 'IN',
        ttl,
        data: fqdn,
      },
      {
        name: fqdn,
        type: 'TXT',
        class: 'IN',
        ttl,
        data: [],
      },
      {
        name: fqdn,
        type: 'SRV',
        class: 'IN',
        ttl,
        data: {
          port: servicePort,
          target: hostname,
          priority: 0,
          weight: 0,
        },
      },
    ];

    const host_answers = await this.addHost({ hostname, ifaceName, ttl });

    this.ifaceResourceRecords.set(ifaceName, [
      ...(this.ifaceResourceRecords.get(ifaceName) ?? []),
      ...answers,
    ]);

    const advertPacket: dnsPacket.Packet = {
      id: 0xcafebabe,
      type: 'response',
      flags: 1024,
      answers: [...host_answers, ...answers].map((e) => {
        (e as any).flush = true;
        return e;
      }),
    };

    console.log(JSON.stringify(advertPacket, null, 4));

    await this.sendPacket(advertPacket, iface);

    setTimeout(this.sendPacket.bind(this, advertPacket, iface), 1000);
  }
}

export default Responder;
