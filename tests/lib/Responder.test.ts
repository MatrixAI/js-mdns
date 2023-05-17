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
    // await responder.advertiseService();
  });
});
