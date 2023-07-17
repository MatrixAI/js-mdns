#define NAPI_VERSION 3

#include <node_api.h>
#include <napi-macros.h>

#include "socketUtils.h"

NAPI_METHOD(disableSocketMulticastAll) {
  NAPI_ARGV(1);
  NAPI_ARGV_INT32(sockfd, 0);

  bool success = DisableMulticastAll(sockfd);

  NAPI_RETURN_INT32(success);
}

NAPI_INIT() {
  NAPI_EXPORT_FUNCTION(disableSocketMulticastAll);
}
