#pragma once

#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include <iostream>
#include <optional>
#include <map>
#include <variant>
#include "enums.h"

using namespace dbps::external;

/**
 * Calculates the total length of level bytes based on encoding attributes.
 * Assumes the input encoding attributes are already validated with the required keys and expected value types.
 * 
 * @param raw Raw binary data (currently unused but kept for future V1 implementation)
 * @param encoding_attribs Converted encoding attributes map
 * @return Total length of level bytes. Throws exceptions if calculation fails or page type is unsupported
 */
int CalculateLevelBytesLength(const std::vector<uint8_t>& raw,
    const std::map<std::string, std::variant<int32_t, bool, std::string>>& encoding_attribs) {
    
    // Helper function to skip V1 RLE level data in raw bytes
    // Returns number of bytes consumed: [4-byte len] + [level bytes indicated by `len`]
    auto SkipV1RLELevel = [&raw](size_t& offset) -> int {
        if (offset + 4 > raw.size()) {
            // TODO: Throw an exception
            return -1;
        }
        uint32_t len = *reinterpret_cast<const uint32_t*>(raw.data() + offset);
        if (offset + 4 + len > raw.size()) {
            // TODO: Throw an exception
            return -1;
        }
        offset += 4 + len;
        return 4 + len;
    };
    
    // Get page_type from the converted attributes
    const std::string& page_type = std::get<std::string>(encoding_attribs.at("page_type"));
    int total_level_bytes = 0;

    if (page_type == "DATA_PAGE_V2") {
        // For DATA_PAGE_V2: sum of definition and repetition level byte lengths
        int32_t def_level_length = std::get<int32_t>(encoding_attribs.at("page_v2_definition_levels_byte_length"));
        int32_t rep_level_length = std::get<int32_t>(encoding_attribs.at("page_v2_repetition_levels_byte_length"));
        total_level_bytes = def_level_length + rep_level_length;
        std::cout << "CalculateLevelBytesLength DATA_PAGE_V2: total_level_bytes=" << total_level_bytes << std::endl;
        
    } else if (page_type == "DATA_PAGE_V1") {
        // Check that encoding types are RLE (instead of BIT_PACKED which is deprecated)
        const std::string& rep_encoding = std::get<std::string>(encoding_attribs.at("page_v1_repetition_level_encoding"));
        const std::string& def_encoding = std::get<std::string>(encoding_attribs.at("page_v1_definition_level_encoding"));
        if (rep_encoding != "RLE" || def_encoding != "RLE") {
            // TODO: Throw an exception
            return -1;
        }

        // if max_rep_level > 0, there are repetition levels bytes. Same for definition levels.
        int32_t max_rep_level = std::get<int32_t>(encoding_attribs.at("data_page_max_repetition_level"));
        int32_t max_def_level = std::get<int32_t>(encoding_attribs.at("data_page_max_definition_level"));
        size_t offset = 0;
        if (max_rep_level > 0) {
            int bytes_skipped = SkipV1RLELevel(offset);
            total_level_bytes += bytes_skipped;
            std::cout << "CalculateLevelBytesLength DATA_PAGE_V1: repetition level bytes skipped=" << bytes_skipped << std::endl;
        }
        if (max_def_level > 0) {
            int bytes_skipped = SkipV1RLELevel(offset);
            total_level_bytes += bytes_skipped;
            std::cout << "CalculateLevelBytesLength DATA_PAGE_V1: definition level bytes skipped=" << bytes_skipped << std::endl;
        }

    } else if (page_type == "DICTIONARY_PAGE") {
        // DICTIONARY_PAGE has no level bytes
        total_level_bytes = 0;

    } else {
        // Unknown page type
        // TODO: Throw an exception
        return -1;
    }

    // Validate that the total level bytes before returning.
    if (total_level_bytes < 0 || total_level_bytes > raw.size()) {
        // TODO: Throw an exception
        return -1;
    }
    return total_level_bytes;

}
