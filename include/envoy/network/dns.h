#pragma once

#include "envoy/common/pure.h"

namespace Network {

/**
 * An asynchronous DNS resolver.
 */
class DnsResolver {
public:
  virtual ~DnsResolver() {}

  /**
   * Called when a resolution attempt is complete.
   * @param address_list supplies the list of resolved IP addresses. The list will be empty if
   *                     the resolution failed.
   */
  typedef std::function<void(std::list<std::string>&& address_list)> ResolveCb;

  /**
   * Initiate an async DNS resolution. FIXFIX need to allow cancel.
   * @param dns_name supplies the DNS name to lookup.
   * @param callback supplies the callback to invoke when the resolution is complete.
   */
  virtual void resolve(const std::string& dns_name, ResolveCb callback) PURE;
};

typedef std::unique_ptr<DnsResolver> DnsResolverPtr;

} // Network
