import { StartStop } from "@matrixai/async-init/dist/StartStop";
import { createSocket, RemoteInfo, Socket } from "dgram";
import { NetworkInterfaceInfo, networkInterfaces } from "os";
import { promisify } from "util";
import dnsPacket from "dns-packet";

const MDNS_PORT = 5353;
const MDNS_TTL = 255;
const GROUP_ADDR = "224.0.0.251";

interface Responder extends StartStop {}
@StartStop()
class Responder extends EventTarget {
  // All the maps here have their keys as an interface's name. The reason for this is we want to be able to tell what interface a DNS packet should be sent from.
  protected ifaces: Map<string, NetworkInterfaceInfo[]>;
  protected ifaceSockets: Map<string, Socket>;
  protected ifaceResourceRecords: Map<string, dnsPacket.Answer[]>;

  constructor() {
    super();
    this.ifaceSockets = new Map();
    this.ifaces = new Map();
    this.ifaceResourceRecords = new Map();

    this.ifaceResourceRecords.set("wlp0s20f3", [
      {
        name: "machine.local",
        type: "A",
        data: "192.168.1.105",
        class: "IN",
        flush: true,
        ttl: 255
      }
    ]);
  }

  public async start(): Promise<void> {
    if (this.ifaces.size === 0) {
      this.scanInterfaces();
    }

    for (const [name, iface] of this.ifaces) {
      // We assume that every network interface only has 1 IPv4 address. This address list should however be a method param so it can be derived from Polykey's bound interfaces.
      const ifaceInfo = iface?.find((iface) => iface.family === "IPv4" && !iface.internal);
      if (typeof ifaceInfo !== "undefined") {
        const socket = createSocket({type: "udp4", reuseAddr: true});

        socket.addListener("close", () => {
          this.ifaceSockets.delete(name);
        });

        socket.addListener("message", (buffer, rinfo) => {
          try {
            const packet = dnsPacket.decode(buffer);
            if (packet.type === "query") {
              this.handleQuery(packet, rinfo);
            }
            else {
            }
          }
          catch (e) {

          }
        });

        await promisify(socket.bind).bind(socket)(MDNS_PORT, "0.0.0.0");

        socket.addMembership(GROUP_ADDR, ifaceInfo.address);
        socket.setTTL(MDNS_TTL);
        socket.setMulticastTTL(MDNS_TTL);
        socket.setMulticastLoopback(true);

        this.ifaceSockets.set(name, socket);
      }
    }
  }

  public async close(): Promise<void> {
    // Close all sockets and clear the sockets map
    await Promise.all([...this.ifaceSockets.values()].map(e => e.close()));
    this.ifaceSockets.clear();
    this.ifaces.clear();
  }

  private scanInterfaces() {
    for (const [name, ifaces] of Object.entries(networkInterfaces())) {
      this.ifaces.set(name, ifaces ?? []);
    }
  }

  private async handleQuery(packet: dnsPacket.Packet, _rinfo: RemoteInfo): Promise<void> {

    const answers: Map<string, dnsPacket.Answer[]> = new Map();

    for (const [ifaceName, hostAnswers] of this.ifaceResourceRecords) {
      const foundAnswers = hostAnswers.filter((answer) =>
        packet.questions?.findIndex((question) =>
          question.name === answer.name
          && question.type === answer.type
          && typeof question.class === "undefined" ? true : (answer as any).class === question.class
        ) !== -1
      );
      if (foundAnswers.length > 0) {
        answers.set(ifaceName, foundAnswers);
      }
    }

    const response = dnsPacket.encode({
      id: 0,
      type: "response",
      flags: 1024,
      answers: [...answers.values()].flat(),
    })

    await Promise.all(
      [...answers.keys()].flatMap((ifaceName) => {
        const socket = this.ifaceSockets.get(ifaceName);
        if (typeof socket !== "undefined") {
          return promisify(socket.send).bind(socket)(response, MDNS_PORT, GROUP_ADDR);
        }
        return [];
      })
    );
  }
}

export default Responder;
