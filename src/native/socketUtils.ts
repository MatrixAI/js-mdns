import path from 'path';
import * as utils from '../utils';

interface SocketUtils {
  disableSocketMulticastAll(socketfd: number): boolean;
}

const projectRoot = path.join(__dirname, '../../');
const prebuildPath = path.join(projectRoot, 'prebuild');

/**
 * Try require on all prebuild targets first, then
 * try require on all npm targets second.
 */
 function requireBinding(targets: Array<string>): SocketUtils {
  const prebuildTargets = targets.map((target) =>
    path.join(prebuildPath, `mdns-${target}.node`),
  );
  for (const prebuildTarget of prebuildTargets) {
    try {
      return require(prebuildTarget);
    } catch (e) {
      if (e.code !== 'MODULE_NOT_FOUND') throw e;
    }
  }
  const npmTargets = targets.map((target) => `@matrixai/mdns-${target}`);
  for (const npmTarget of npmTargets) {
    try {
      return require(npmTarget);
    } catch (e) {
      if (e.code !== 'MODULE_NOT_FOUND') throw e;
    }
  }
  throw new Error(
    `Failed requiring possible native bindings: ${prebuildTargets.concat(
      npmTargets,
    )}`,
  );
}

let nativeBinding: SocketUtils;

switch (process.platform) {
  case 'linux':
    switch (process.arch) {
      case 'x64':
        nativeBinding = requireBinding(['linux-x64']);
        break;
      case 'arm64':
        nativeBinding = requireBinding(['linux-arm64']);
        break;
      case 'arm':
        nativeBinding = requireBinding(['linux-arm']);
        break;
      default:
        throw new Error(`Unsupported architecture on Linux: ${process.arch}`);
    }
    break;
  default:
    nativeBinding = {
      disableSocketMulticastAll: () => false
    }
}

export default nativeBinding;

export type { SocketUtils };
