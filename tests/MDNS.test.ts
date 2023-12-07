import type { Hostname } from '@/types';
import Logger, { LogLevel, StreamHandler } from '@matrixai/logger';
import * as events from '@/events';
import MDNS from '@/MDNS';

describe(MDNS.name, () => {
  const logger = new Logger(MDNS.name, LogLevel.WARN, [new StreamHandler()]);

  let mdns1: MDNS;
  let mdns2: MDNS;

  const mdnsGroups = ['224.0.0.250', 'ff02::fa17'];
  const mdnsPort = 64023;

  beforeEach(async () => {
    mdns1 = new MDNS({ logger });
    mdns2 = new MDNS({ logger });
  });
  afterEach(async () => {
    await mdns1.stop();
    await mdns2.stop();
  });
  test('advertisement', async () => {
    const mdns1Hostname = 'polykey1' as Hostname;
    const mdns2Hostname = 'polykey2' as Hostname;
    await mdns1.start({
      hostname: mdns1Hostname,
      port: mdnsPort,
      groups: mdnsGroups,
    });
    await mdns2.start({
      hostname: mdns2Hostname,
      port: mdnsPort,
      groups: mdnsGroups,
    });
    const service = {
      name: 'test',
      port: mdnsPort,
      protocol: 'udp',
      type: 'polykey',
    } as Parameters<typeof MDNS.prototype.registerService>[0];
    mdns2.registerService(service);
    await new Promise((resolve, reject) => {
      mdns1.addEventListener(
        events.EventMDNSService.name,
        (e: events.EventMDNSService) => {
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
        },
      );
    });
  });
  test('query', async () => {
    const mdns1Hostname = 'polykey1' as Hostname;
    const mdns2Hostname = 'polykey2' as Hostname;
    await mdns1.start({
      hostname: mdns1Hostname,
      port: mdnsPort,
      groups: mdnsGroups,
      advertise: false,
    });
    await mdns2.start({
      hostname: mdns2Hostname,
      port: mdnsPort,
      groups: mdnsGroups,
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
      mdns1.addEventListener(
        events.EventMDNSService.name,
        (e: events.EventMDNSService) => {
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
        },
      );
    });
  });
  describe('lifecycle', () => {
    test('starting and stopping a query', async () => {
      const mdns1Hostname = 'polykey1' as Hostname;
      await mdns1.start({
        hostname: mdns1Hostname,
        port: mdnsPort,
        groups: mdnsGroups,
        advertise: false,
      });
      const service = {
        name: 'test',
        port: mdnsPort,
        protocol: 'udp',
        type: 'polykey',
        advertise: false,
      } as Parameters<typeof MDNS.prototype.startQuery>[0];
      mdns1.startQuery(service);
      mdns1.stopQuery(service);
      // @ts-ignore: Kidnap protected property
      expect(mdns1.stoppingTasks.size).toBe(1);
      await mdns1.stop();
      // @ts-ignore: Kidnap protected property
      expect(mdns1.stoppingTasks.size).toBe(0);
    });
    test('starting and stopping multiple queries', async () => {
      const mdns1Hostname = 'polykey1' as Hostname;
      await mdns1.start({
        hostname: mdns1Hostname,
        port: mdnsPort,
        groups: mdnsGroups,
        advertise: false,
      });
      const service = {
        name: 'test',
        port: mdnsPort,
        protocol: 'udp',
        type: 'polykey',
      } as Parameters<typeof MDNS.prototype.startQuery>[0];
      mdns1.startQuery(service);
      mdns1.startQuery(service);
      mdns1.stopQuery(service);
      // @ts-ignore: Kidnap protected property
      expect(mdns1.stoppingTasks.size).toBe(2);
      await mdns1.stop();
      // @ts-ignore: Kidnap protected property
      expect(mdns1.stoppingTasks.size).toBe(0);
    });
    test('starting multiple advertisements', async () => {
      const mdns1Hostname = 'polykey1' as Hostname;
      await mdns1.start({
        hostname: mdns1Hostname,
        port: mdnsPort,
        groups: mdnsGroups,
        advertise: false,
      });
      const service = {
        name: 'test',
        port: mdnsPort,
        protocol: 'udp',
        type: 'polykey',
      } as Parameters<typeof MDNS.prototype.registerService>[0];
      mdns1.registerService(service);
      mdns1.registerService(service);
      // @ts-ignore: Kidnap protected property
      expect(mdns1.stoppingTasks.size).toBe(1);
      await mdns1.stop();
      // @ts-ignore: Kidnap protected property
      expect(mdns1.stoppingTasks.size).toBe(0);
    });
    test('starting and stopping multiple queries and advertisements', async () => {
      const mdns1Hostname = 'polykey1' as Hostname;
      await mdns1.start({
        hostname: mdns1Hostname,
        port: mdnsPort,
        groups: mdnsGroups,
        advertise: false,
      });
      const service = {
        name: 'test',
        port: mdnsPort,
        protocol: 'udp',
        type: 'polykey',
      } as Parameters<typeof MDNS.prototype.registerService>[0];
      mdns1.startQuery(service);
      mdns1.startQuery(service);
      mdns1.stopQuery(service);
      mdns1.registerService(service);
      mdns1.registerService(service);
      // @ts-ignore: Kidnap protected property
      expect(mdns1.stoppingTasks.size).toBe(3);
      await mdns1.stop();
      // @ts-ignore: Kidnap protected property
      expect(mdns1.stoppingTasks.size).toBe(0);
    });
  });
});
