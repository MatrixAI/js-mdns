import { AbstractError } from '@matrixai/errors';

class ErrorMDNS<T> extends AbstractError<T> {
  static description = 'MDNS Error';
}

class ErrorMDNSRunning<T> extends ErrorMDNS<T> {
  static description = 'MDNS is running';
}

class ErrorMDNSNotRunning<T> extends ErrorMDNS<T> {
  static description = 'MDNS is not running';
}

class ErrorMDNSInvalidMulticastAddress<T> extends ErrorMDNS<T> {
  static description = 'MDNS cannot process the invalid multicast address';
}

class ErrorMDNSInterfaceRange<T> extends ErrorMDNS<T> {
  static description = 'MDNS interface range error';
}


class ErrorMDNSPacket<T> extends ErrorMDNS<T> {
  static description = 'DNS Packet error';
}

class ErrorMDNSPacketParse<T> extends ErrorMDNSPacket<T> {
  static description = 'DNS Packet parse error';
}

class ErrorMDNSPacketGenerate<T> extends ErrorMDNSPacket<T> {
  static description = 'DNS Packet generation error';
}
class ErrorMDNSSocket<T> extends ErrorMDNS<T> {
  static description = 'MDNS socket error';
}


class ErrorMDNSSocketInternal<T> extends ErrorMDNS<T> {
  static description = 'MDNS socket internal error';
}

class ErrorMDNSSocketInvalidBindAddress<T> extends ErrorMDNSSocket<T> {
  static description = 'MDNS cannot bind to the specified address';
}

class ErrorMDNSSocketInvalidSendAddress<T> extends ErrorMDNSSocket<T> {
  static description = 'MDNS cannot send to the specified address';
}

class ErrorMDNSSocketInvalidReceiveAddress<T> extends ErrorMDNSSocket<T> {
  static description = 'MDNS cannot correctly parse the receive address';
}

class ErrorMDNSSocketSendFailed<T> extends ErrorMDNSSocket<T> {

}

export {
  ErrorMDNS,
  ErrorMDNSRunning,
  ErrorMDNSNotRunning,
  ErrorMDNSInterfaceRange,
  ErrorMDNSInvalidMulticastAddress,
  ErrorMDNSPacket,
  ErrorMDNSPacketParse,
  ErrorMDNSPacketGenerate,
  ErrorMDNSSocket,
  ErrorMDNSSocketInternal,
  ErrorMDNSSocketInvalidBindAddress,
  ErrorMDNSSocketInvalidSendAddress,
  ErrorMDNSSocketInvalidReceiveAddress,
  ErrorMDNSSocketSendFailed
};
