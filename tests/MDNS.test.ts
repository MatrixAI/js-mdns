import type { MDNSServiceEvent, MDNSServiceRemovedEvent } from '@/events';
import type { Host, Hostname, Port } from '@/types';
import { Timer } from '@matrixai/timer';
import MDNS from '@/MDNS';
import { testUtility } from './utils';
import dgram from 'dgram';
import { EventEmitter } from 'stream';


describe(MDNS.name, () => {
  let mdns1: MDNS;
  let mdns2: MDNS;

  beforeEach(async () => {
    mdns1 = new MDNS();
    mdns2 = new MDNS();
  });
  afterEach(async () => {
    await mdns1.stop();
    await mdns2.stop();
  });
  test('advertisement', async () => {
    const mdnsPort = 1234 as Port;
    const mdns1Hostname = 'polykey1' as Hostname;
    const mdns2Hostname = 'polykey2' as Hostname;
    await mdns1.start({ hostname: mdns1Hostname, port: mdnsPort });
    await mdns2.start({ hostname: mdns2Hostname, port: mdnsPort });
    const service = {
      name: 'test',
      port: mdnsPort,
      protocol: "udp",
      type: 'polykey',
    };
    mdns2.registerService(service as any)
    await new Promise((resolve, reject) => {
      mdns1.addEventListener('service', (e: MDNSServiceEvent) => {
        try {
          expect(e.detail.name).toBe(service.name);
          expect(e.detail.port).toBe(service.port);
          expect(e.detail.protocol).toBe(service.protocol);
          expect(e.detail.type).toBe(service.type);
          expect(e.detail.hostname).toBe(mdns2Hostname + '.local');
          resolve(null);
        }
        catch (e) {
          reject(e);
        }
      });
    });
  });
  test('query', async () => {
    const mdnsPort = 1234 as Port;
    const mdns1Hostname = 'polykey1' as Hostname;
    const mdns2Hostname = 'polykey2' as Hostname;
    await mdns1.start({ hostname: mdns1Hostname, port: mdnsPort, advertise: false });
    await mdns2.start({ hostname: mdns2Hostname, port: mdnsPort, advertise: false });
    const service = {
      name: 'test',
      port: 1234,
      protocol: 'udp',
      type: 'polykey',
      advertise: false,
    };
    mdns2.registerService(service as any);
    mdns1.startQuery(service as any);
    await new Promise((resolve, reject) => {
      mdns1.addEventListener('service', (e: MDNSServiceEvent) => {
        try {
          expect(e.detail.name).toBe(service.name);
          expect(e.detail.port).toBe(service.port);
          expect(e.detail.protocol).toBe(service.protocol);
          expect(e.detail.type).toBe(service.type);
          expect(e.detail.hostname).toBe(mdns2Hostname + '.local');
          resolve(null);
        }
        catch (e) {
          reject(e);
        }
      });
    });
  });
});
