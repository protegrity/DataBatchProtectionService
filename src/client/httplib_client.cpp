#include "httplib_client.h"

HttplibClient::HttplibClient(const std::string& base_url)
    : base_url_(base_url) {
}

HttpClientInterface::HttpResponse HttplibClient::Get(const std::string& endpoint) {
    try {
        httplib::Client client(base_url_);
        
        client.set_connection_timeout(10);
        client.set_read_timeout(30);
        
        // Set headers to indicate JSON responses
        httplib::Headers headers = {
            {"Accept", "application/json"},
            {"User-Agent", "DBPSApiClient/1.0"}
        };
        
        // Make the GET request
        auto result = client.Get(endpoint, headers);
        
        if (!result) {
            return HttpResponse(0, "", "HTTP GET request failed: no response received");
        }
        
        return HttpResponse(result->status, result->body);
        
    } catch (const std::exception& e) {
        return HttpResponse(0, "", "GET request failed for endpoint " + endpoint + ": " + std::string(e.what()));
    }
}

HttpClientInterface::HttpResponse HttplibClient::Post(const std::string& endpoint, const std::string& json_body) {
    try {
        httplib::Client client(base_url_);
        
        client.set_connection_timeout(10);
        client.set_read_timeout(30);
        
        // Set headers for JSON content
        httplib::Headers headers = {
            {"Content-Type", "application/json"},
            {"Accept", "application/json"},
            {"User-Agent", "DBPSApiClient/1.0"}
        };
        
        // Make the POST request
        auto result = client.Post(endpoint, headers, json_body, "application/json");
        
        if (!result) {
            return HttpResponse(0, "", "HTTP POST request failed: no response received");
        }
        
        return HttpResponse(result->status, result->body);
        
    } catch (const std::exception& e) {
        return HttpResponse(0, "", "HTTP POST request failed for endpoint " + endpoint + ": " + std::string(e.what()));
    }
}
