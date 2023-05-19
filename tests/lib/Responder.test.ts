import Responder from '@/lib/Responder';
import { testUtility } from './utils';

describe('Responder', () => {
  let library: Responder | null;

  beforeAll(() => {
    library = new Responder();
    // A noop test utility
    // demonstrates using utils inside tests
    testUtility();
  });

  afterAll(() => {
    library = null;
  });

  test('some arbitrary test', async () => {
    const responder = new Responder();
    await responder.start();
    await responder.advertiseService({ ifaceName: "wlp0s20f3", hostname: "123.local", servicePort: 1234, serviceType: "_polykey._udp" });
    // Await responder.advertiseService();
  });
});
