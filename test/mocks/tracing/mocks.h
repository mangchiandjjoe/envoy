#pragma once

#include "envoy/tracing/http_tracer.h"

namespace Tracing {

class MockTracingConfig : public TracingConfig {
public:
  MockTracingConfig() {}
  ~MockTracingConfig() {}

  MOCK_CONST_METHOD0(operationName, const std::string&());
};

class MockSpan : public Span {
public:
  MockSpan() {}
  ~MockSpan() {}

  MOCK_METHOD2(finishSpan, void((const Http::AccessLog::RequestInfo& request_info,
                                 const Http::HeaderMap& response_headers)));
};

class MockTracingContext : public TracingContext {
public:
  MockTracingContext() {}
  ~MockTracingContext() {}

  MOCK_METHOD2(startSpan, void(const Http::AccessLog::RequestInfo& request_info,
                               const Http::HeaderMap& request_headers));
  MOCK_METHOD2(finishSpan, void(const Http::AccessLog::RequestInfo& request_info,
                                const Http::HeaderMap* response_headers));
};

class MockHttpTracer : public HttpTracer {
public:
  MockHttpTracer() {}
  ~MockHttpTracer() {}

  void initializeDriver(TracingDriverPtr&& driver) override { initializeDriver_(driver); }

  MOCK_METHOD1(initializeDriver_, void(TracingDriverPtr& driver));
  MOCK_METHOD3(startSpan,
               Span*(const Http::AccessLog::RequestInfo& request_info,
                     const Http::HeaderMap& request_headers, const TracingConfig& tracing_config));
};

class MockTracingDriver : public TracingDriver {
public:
  MockTracingDriver() {}
  ~MockTracingDriver() {}

  MOCK_METHOD3(startSpan,
               Span*(const Http::AccessLog::RequestInfo& request_info,
                     const Http::HeaderMap& request_headers, const TracingConfig& tracing_config));
};

} // Tracing