#pragma once

#include "http_client_interface.h"
#include <httplib.h>

class HttplibClient : public HttpClientInterface {
public:
    explicit HttplibClient(const std::string& base_url);
    
    /**
     * Performs an HTTP GET request to the specified endpoint
     * 
     * @param endpoint The endpoint path to request (e.g., "/healthz")
     * @return HttpResponse containing status code, response body, and any error message
     * 
     * @note Connections are not reused - a new connection is established for each request
     * @note Requests are not retried on failure
     * @note Requests are not enqueued - they are sent immediately
     */
    HttpResponse Get(const std::string& endpoint) override;
    
    /**
     * Performs an HTTP POST request to the specified endpoint with JSON body
     * 
     * @param endpoint The endpoint path to request (e.g., "/encrypt")
     * @param json_body The JSON payload to send in the request body
     * @return HttpResponse containing status code, response body, and any error message
     * 
     * @note Connections are not reused - a new connection is established for each request
     * @note Requests are not retried on failure
     * @note Requests are not enqueued - they are sent immediately
     */
    HttpResponse Post(const std::string& endpoint, const std::string& json_body) override;

private:
    std::string base_url_;
};
