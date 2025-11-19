// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#pragma once

#include <map>
#include <optional>
#include <string>
#include <iostream>
#include "enums.h"
#include "enum_utils.h"
#include <nlohmann/json.hpp>

// TODO: Define all constant/literal (e.g. "server_url", "user_id", "page_encoding") as constants here.

namespace dbps::external {

/**
 * Shared utility functions for DataBatchProtectionAgent implementations
 * These functions are used by both RemoteDataBatchProtectionAgent and LocalDataBatchProtectionAgent
 */

/**
 * Extract server_url from connection_config map
 * 
 * @param connection_config Map of connection configuration key-value pairs
 * @return server_url value if found, std::nullopt otherwise
 * 
 * Expected key: "server_url" with value as the server URL string
 */
inline std::optional<std::string> ExtractServerUrl(const std::map<std::string, std::string>& connection_config) {
    auto it = connection_config.find("server_url");
    if (it != connection_config.end()) {
        return it->second;
    }
    return std::nullopt;
}

/**
 * Extract user_id from app_context JSON string
 * 
 * @param app_context JSON string containing user_id field
 * @return user_id value if found and valid, std::nullopt otherwise
 * 
 * Expected JSON format: {"user_id": "some_user_id", ...}
 */
inline std::optional<std::string> ExtractUserId(const std::string& app_context) {
    try {
        auto json = nlohmann::json::parse(app_context);
        if (json.contains("user_id") && json["user_id"].is_string()) {
            std::string user_id = json["user_id"];
            if (!user_id.empty()) {
                return user_id;
            }
        }
    } catch (const nlohmann::json::exception& e) {
        std::cerr << "ERROR: ExtractUserId() - Failed to parse app_context JSON: " << e.what() << std::endl;
    }
    return std::nullopt;
}

/**
 * Extract page_encoding from encoding_attributes map and convert to Format::type
 * 
 * @param encoding_attributes Map of encoding attribute key-value pairs
 * @return Format::type value if page_encoding found and valid, std::nullopt otherwise
 * 
 * Expected key: "page_encoding" with value as string representation of Format enum
 */
inline std::optional<Format::type> ExtractPageEncoding(const std::map<std::string, std::string>& encoding_attributes) {
    using namespace dbps::enum_utils;
    auto it = encoding_attributes.find("page_encoding");
    if (it != encoding_attributes.end()) {
        const std::string& encoding_str = it->second;
        auto format_opt = to_format_enum(encoding_str);
        if (format_opt.has_value()) {
            return format_opt.value();
        } else {
            std::cerr << "ERROR: ExtractPageEncoding() - Unknown page_encoding: " << encoding_str << std::endl;
            return std::nullopt;
        }
    }
    // Return nullopt if page_encoding not found
    std::cerr << "ERROR: ExtractPageEncoding() - page_encoding not found." << std::endl;
    return std::nullopt;
}

} // namespace dbps::external

