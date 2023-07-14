#include <sys/socket.h>
#include <netinet/in.h>

bool DisableMulticastAll(int sockfd) {
  int enable = 0;
  int enableSize = sizeof(enable);
  bool success = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_ALL, &enable, enableSize) >= 0;
  success = success && (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_ALL, &enable, enableSize) >= 0);
  return success;
}
