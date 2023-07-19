import type { MDNSServiceEvent } from '@/events';
import type { Hostname, Port } from '@/types';
import MDNS from '@/MDNS';

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
      protocol: 'udp',
      type: 'polykey',
    } as Parameters<typeof MDNS.prototype.registerService>[0];
    mdns2.registerService(service);
    await new Promise((resolve, reject) => {
      mdns1.addEventListener('service', (e: MDNSServiceEvent) => {
        try {
          expect(e.detail.name).toBe(service.name);
          expect(e.detail.port).toBe(service.port);
          expect(e.detail.protocol).toBe(service.protocol);
          expect(e.detail.type).toBe(service.type);
          expect(e.detail.hostname).toBe(mdns2Hostname + '.local');
          resolve(null);
        } catch (e) {
          reject(e);
        }
      });
    });
  });
  test('query', async () => {
    const mdnsPort = 1234 as Port;
    const mdns1Hostname = 'polykey1' as Hostname;
    const mdns2Hostname = 'polykey2' as Hostname;
    await mdns1.start({
      hostname: mdns1Hostname,
      port: mdnsPort,
      advertise: false,
    });
    await mdns2.start({
      hostname: mdns2Hostname,
      port: mdnsPort,
      advertise: false,
    });
    const service = {
      name: 'test',
      port: mdnsPort,
      protocol: 'udp',
      type: 'polykey',
      advertise: false,
    } as Parameters<typeof MDNS.prototype.registerService>[0];
    mdns2.registerService(service);
    mdns1.startQuery(service);
    await new Promise((resolve, reject) => {
      mdns1.addEventListener('service', (e: MDNSServiceEvent) => {
        try {
          expect(e.detail.name).toBe(service.name);
          expect(e.detail.port).toBe(service.port);
          expect(e.detail.protocol).toBe(service.protocol);
          expect(e.detail.type).toBe(service.type);
          expect(e.detail.hostname).toBe(mdns2Hostname + '.local');
          resolve(null);
        } catch (e) {
          reject(e);
        }
      });
    });
  });
});
