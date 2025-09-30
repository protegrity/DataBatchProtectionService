#pragma once

#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include <optional>
#include <map>
#include <variant>
#include "enums.h"

using namespace dbps::external;

/**
 * Decodes raw binary data into a human-readable string for debugging/logging.
 * Returns "decode error" on failure or "unsupported type" for unimplemented types.
 * For FIXED_LEN_BYTE_ARRAY, datatype_length specifies the fixed length of each element.
 * leading_bytes_to_strip specifies the number of bytes to remove from the beginning of raw data.
 */
std::string PrintPlainDecoded(const std::vector<uint8_t>& raw, Type::type physical_type,
    std::optional<int> datatype_length = std::nullopt, int leading_bytes_to_strip = 0) {

    // TODO: Remove these strings and use exceptions
    static constexpr const char* DECODE_ERROR_STR = "Unknown encoding";
    static constexpr const char* UNSUPPORTED_TYPE_STR = "Unsupported type";

    // Validate leading_bytes_to_strip parameter
    if (leading_bytes_to_strip < 0) {
        return "Number of leading bytes to strip must be >= 0";
    }
    if (leading_bytes_to_strip > 0 && raw.size() <= leading_bytes_to_strip) {
        return "Number of leading bytes to strip must be < data size";
    }

    // Create adjusted data vector by stripping leading bytes (or use original if 0)
    std::vector<uint8_t> adjusted_raw;
    if (leading_bytes_to_strip == 0) {
        adjusted_raw = raw;  // No stripping needed
    } else {
        adjusted_raw = std::vector<uint8_t>(raw.begin() + leading_bytes_to_strip, raw.end());
    }

    auto require = [&](bool cond) -> bool { return cond; };

    const uint8_t* raw_data = adjusted_raw.data();
    const size_t raw_size = adjusted_raw.size();

    std::ostringstream out;

    switch (physical_type) {
        case Type::INT32: {
            if (!require((raw_size % sizeof(int32_t)) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded INT32 values:\n";
            const int32_t* v = reinterpret_cast<const int32_t*>(raw_data);
            size_t count = raw_size / sizeof(int32_t);
            for (size_t i = 0; i < count; ++i) { 
                out << "  [" << i << "] " << v[i] << "\n"; 
            }
            break;
        }

        case Type::INT64: {
            if (!require((raw_size % sizeof(int64_t)) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded INT64 values:\n";
            const int64_t* v = reinterpret_cast<const int64_t*>(raw_data);
            size_t count = raw_size / sizeof(int64_t);
            for (size_t i = 0; i < count; ++i) { 
                out << "  [" << i << "] " << v[i] << "\n"; 
            }
            break;
        }

        case Type::FLOAT: {
            if (!require((raw_size % sizeof(float)) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded FLOAT values:\n";
            const float* v = reinterpret_cast<const float*>(raw_data);
            size_t count = raw_size / sizeof(float);
            for (size_t i = 0; i < count; ++i) { 
                out << "  [" << i << "] " << v[i] << "\n"; 
            }
            break;
        }

        case Type::DOUBLE: {
            if (!require((raw_size % sizeof(double)) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded DOUBLE values:\n";
            const double* v = reinterpret_cast<const double*>(raw_data);
            size_t count = raw_size / sizeof(double);
            for (size_t i = 0; i < count; ++i) { 
                out << "  [" << i << "] " << v[i] << "\n"; 
            }
            break;
        }

        case Type::INT96: {
            if (!require((raw_size % 12) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded INT96 values ([lo, mid, hi] 32-bit words):\n";
            const uint8_t* p = raw_data;
            const uint8_t* last_byte = raw_data + raw_size;
            int idx = 0;
            while (p + 12 <= last_byte) {
                uint32_t lo, mid, hi;
                std::memcpy(&lo,  p + 0,  4);  // little-endian assumed
                std::memcpy(&mid, p + 4,  4);
                std::memcpy(&hi,  p + 8,  4);
                out << "  [" << idx++ << "] [" << lo << ", " << mid << ", " << hi << "]\n";
                p += 12;
            }
            break;
        }

        case Type::BYTE_ARRAY: {
            out << "Decoded BYTE_ARRAY values:\n";
            const uint8_t* p = raw_data;
            const uint8_t*  last_byte = raw_data + raw_size;
            int idx = 0;
            while (p + 4 <= last_byte) {
                uint32_t len;
                std::memcpy(&len, p, sizeof(len));  // little-endian assumed
                p += 4;
                if (!require(p + len <= last_byte)) return DECODE_ERROR_STR;
                const char* s = reinterpret_cast<const char*>(p);
                out << "  [" << idx++ << "] \"" << std::string(s, s + len) << "\"\n";
                p += len;
            }
            if (!require(p == last_byte)) return DECODE_ERROR_STR;
            break;
        }

        case Type::FIXED_LEN_BYTE_ARRAY: {
            if (!datatype_length.has_value() || datatype_length.value() <= 0 || (raw_size % datatype_length.value()) != 0) {
                return DECODE_ERROR_STR;
            }
            int fixed_length = datatype_length.value();
            out << "Decoded FIXED_LEN_BYTE_ARRAY (length=" << fixed_length << "):\n";
            size_t element_count = raw_size / fixed_length;
            for (size_t i = 0; i < element_count; ++i) {
                const char* element_start = reinterpret_cast<const char*>(raw_data + i * fixed_length);
                out << "  [" << i << "] \"" << std::string(element_start, fixed_length) << "\"\n";
            }
            break;
        }

        // This is a known type, but passed as "undefined" by the API caller intentionally.
        case Type::UNDEFINED: {
            out << "Decoded UNDEFINED type (raw bytes):\n";
            const char* s = reinterpret_cast<const char*>(raw_data);
            out << "  \"" << std::string(s, s + raw_size) << "\"\n";
            break;
        }

        default:
            return UNSUPPORTED_TYPE_STR;
    }

    return out.str();
}

/**
 * Calculates the total length of level bytes based on encoding attributes.
 * 
 * @param raw Raw binary data (currently unused but kept for future V1 implementation)
 * @param encoding_attribs Converted encoding attributes map
 * @return Total length of level bytes. Throws exceptions if calculation fails or page type is unsupported
 */
int CalculateLevelBytesLength(const std::vector<uint8_t>& raw,
    const std::map<std::string, std::variant<int, bool, std::string>>& encoding_attribs) {
    
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
        int def_level_length = std::get<int>(encoding_attribs.at("page_v2_definition_levels_byte_length"));
        int rep_level_length = std::get<int>(encoding_attribs.at("page_v2_repetition_levels_byte_length"));
        total_level_bytes = def_level_length + rep_level_length;
        
    } else if (page_type == "DATA_PAGE_V1") {
        int max_rep_level = std::get<int>(encoding_attribs.at("data_page_max_repetition_level"));
        int max_def_level = std::get<int>(encoding_attribs.at("data_page_max_definition_level"));

        // if max_rep_level > 0, there are repetition levels bytes. Same for definition levels.
        size_t offset = 0;
        if (max_rep_level > 0) {
            total_level_bytes += SkipV1RLELevel(offset);
        }
        if (max_def_level > 0) {
            total_level_bytes += SkipV1RLELevel(offset);
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
