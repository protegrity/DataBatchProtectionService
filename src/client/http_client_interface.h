#pragma once

#include <string>

/**
 * Interface for HTTP client implementations.
 * 
 * Thread Safety: Implementations must be thread-safe for concurrent calls.
 * Multiple threads may call Get() and Post() methods simultaneously on the same instance.
 */
class HttpClientInterface {
public:
    virtual ~HttpClientInterface() = default;
    
    struct HttpResponse {
        int status_code;
        std::string result;
        std::string error_message;
        
        HttpResponse() : status_code(0), result(""), error_message("") {}
        
        HttpResponse(int code, std::string response_result) 
            : status_code(code), result(std::move(response_result)), error_message("") {}
        
        HttpResponse(int code, std::string response_result, std::string error) 
            : status_code(code), result(std::move(response_result)), error_message(std::move(error)) {}
    };
    
    virtual HttpResponse Get(const std::string& endpoint) = 0;
    virtual HttpResponse Post(const std::string& endpoint, const std::string& json_body) = 0;
};
