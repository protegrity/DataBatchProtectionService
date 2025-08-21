#pragma once

#include "http_client_interface.h"
#include <httplib.h>

class HttplibClient : public HttpClientInterface {
public:
    explicit HttplibClient(const std::string& base_url);
    
    HttpResponse Get(const std::string& endpoint) override;
    HttpResponse Post(const std::string& endpoint, const std::string& json_body) override;

private:
    std::string base_url_;
};
