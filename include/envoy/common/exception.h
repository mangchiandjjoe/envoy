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
 * Resource is not ready but it is not recoverable
 */
class EnvoyResourceDependencyFatalException : public EnvoyException {
public:
  EnvoyResourceDependencyFatalException(const std::string& message) : EnvoyException(message) {}
};

} // namespace Envoy
