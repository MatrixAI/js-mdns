#include <sys/socket.h>
#include <netinet/in.h>

bool DisableMulticastAll(int sockfd) {
  int enable = 0;
  int enablesize = sizeof(enable);
  bool success = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_ALL, &enable, enablesize) >= 0;

  struct sockaddr_storage sockaddr;
  socklen_t sockaddrsize = sizeof(sockaddr);
  getsockname(sockfd, (struct sockaddr *) &sockaddr, &sockaddrsize);

  if (sockaddr.ss_family == AF_INET6) {
    success = success && (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_ALL, &enable, enablesize) >= 0);
  }

  return success;
}
