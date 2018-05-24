#pragma once

#include <stdexcept>
#include <string>

namespace Envoy {
/**
 * Base class for all envoy exceptions.
 */
class EnvoyException : public std::runtime_error {
public:
  EnvoyException(const std::string& message) : std::runtime_error(message) {}
};

/**
 * Resource is not ready but it is recoverable
 */
class EnvoyResourceDependencyException : public EnvoyException {
public:
  EnvoyResourceDependencyException(const std::string& message) : EnvoyException(message) {}
};


/**
 * Resource is not ready but it is recoverable
 */
class EnvoyClusterDependencyException : public EnvoyException {
 public:
  EnvoyClusterDependencyException(const std::string& message, const std::string name)
      : EnvoyException(message),
        cluster_name(name) {
  }

  const std::string cluster_name;
};

}  // namespace Envoy
