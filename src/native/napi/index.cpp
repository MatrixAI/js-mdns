#define NAPI_VERSION 3

#include <netdb.h>
#include <netinet/in.h>

#include <napi.h>
#include <node_api.h>

#include "socketUtils.h"

Napi::Value disableSocketMulticastAll(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  int sockfd = info[0].As<Napi::Number>().Int32Value();
  bool success = DisableMulticastAll(sockfd);
  return Napi::Boolean::New(env, success);
}

Napi::Value bindDgramFd(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  Napi::Object dgramSocket = info[0].As<Napi::Object>();
  Napi::String udpType = dgramSocket.Get("type").As<Napi::String>();

  int family = AF_INET;
  if (udpType.Utf8Value().compare("udp6") == 0) {
    family = AF_INET6;
  }

  int sockfd = socket(family, SOCK_DGRAM, 0);

  Napi::Object bindOptions = info[1].As<Napi::Object>();
  Napi::Value addressValue = bindOptions.Get("address");
  Napi::Value portValue = bindOptions.Get("port");

  std::string address;
  if (addressValue.IsString()) {
    address = addressValue.As<Napi::String>().Utf8Value();
  } else {
    if (family == AF_INET) {
      address = "0.0.0.0";
    } else {
      address = "::0";
    }
  }

  addrinfo *result;
  if (getaddrinfo(address.c_str(), NULL, NULL, &result) != 0) {
    Napi::Error::New(env, "Invalid Address").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (portValue.IsNumber()) {
    int port = portValue.As<Napi::Number>().Int32Value();
    if (result->ai_family == AF_INET) {
      ((sockaddr_in *)result->ai_addr)->sin_port = htons(port);
    } else {
      ((sockaddr_in6 *)result->ai_addr)->sin6_port = htons(port);
    }
  }

  bind(sockfd, result->ai_addr, result->ai_addrlen);
  return Napi::Number::New(env, sockfd);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "disableSocketMulticastAll"),
              Napi::Function::New(env, disableSocketMulticastAll));
  return exports;
}

NODE_API_MODULE(addon, Init)
