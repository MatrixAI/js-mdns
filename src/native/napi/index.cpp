#define NAPI_VERSION 3

#include <napi.h>
#include <node_api.h>

#include "socketUtils.h"

Napi::Value disableSocketMulticastAll(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  int sockfd = info[0].As<Napi::Number>().Int32Value();
  bool success = DisableMulticastAll(sockfd);
  return Napi::Boolean::New(env, success);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "disableSocketMulticastAll"),
              Napi::Function::New(env, disableSocketMulticastAll));
  return exports;
}

NODE_API_MODULE(addon, Init)
