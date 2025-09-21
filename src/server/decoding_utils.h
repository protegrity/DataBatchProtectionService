#pragma once

#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include <optional>
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
    static constexpr const char* DECODE_ERROR_STR = "Unknown encoding";
    static constexpr const char* UNSUPPORTED_TYPE_STR = "Unsupported type";

    // Validate leading_bytes_to_strip parameter
    if (leading_bytes_to_strip < 0) {
        return "Invalid leading_bytes_to_strip: must be >= 0";
    }
    if (leading_bytes_to_strip > 0 && raw.size() <= leading_bytes_to_strip) {
        return "Invalid leading_bytes_to_strip: must be < data size";
    }

    // Create adjusted data vector by stripping leading bytes (or use original if 0)
    std::vector<uint8_t> adjusted_raw;
    if (leading_bytes_to_strip == 0) {
        adjusted_raw = raw;  // No stripping needed
    } else {
        adjusted_raw = std::vector<uint8_t>(raw.begin() + leading_bytes_to_strip, raw.end());
    }

    auto require = [&](bool cond) -> bool { return cond; };

    const uint8_t* data = adjusted_raw.data();
    const uint8_t* end  = data + adjusted_raw.size();

    std::ostringstream out;

    switch (physical_type) {
        case Type::INT32: {
            if (!require((adjusted_raw.size() % sizeof(int32_t)) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded INT32 values:\n";
            const int32_t* v = reinterpret_cast<const int32_t*>(data);
            size_t count = adjusted_raw.size() / sizeof(int32_t);
            for (size_t i = 0; i < count; ++i) { 
                out << "  [" << i << "] " << v[i] << "\n"; 
            }
            break;
        }

        case Type::INT64: {
            if (!require((adjusted_raw.size() % sizeof(int64_t)) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded INT64 values:\n";
            const int64_t* v = reinterpret_cast<const int64_t*>(data);
            size_t count = adjusted_raw.size() / sizeof(int64_t);
            for (size_t i = 0; i < count; ++i) { 
                out << "  [" << i << "] " << v[i] << "\n"; 
            }
            break;
        }

        case Type::FLOAT: {
            if (!require((adjusted_raw.size() % sizeof(float)) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded FLOAT values:\n";
            const float* v = reinterpret_cast<const float*>(data);
            size_t count = adjusted_raw.size() / sizeof(float);
            for (size_t i = 0; i < count; ++i) { 
                out << "  [" << i << "] " << v[i] << "\n"; 
            }
            break;
        }

        case Type::DOUBLE: {
            if (!require((adjusted_raw.size() % sizeof(double)) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded DOUBLE values:\n";
            const double* v = reinterpret_cast<const double*>(data);
            size_t count = adjusted_raw.size() / sizeof(double);
            for (size_t i = 0; i < count; ++i) { 
                out << "  [" << i << "] " << v[i] << "\n"; 
            }
            break;
        }

        case Type::INT96: {
            if (!require((adjusted_raw.size() % 12) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded INT96 values ([lo, mid, hi] 32-bit words):\n";
            const uint8_t* p = data;
            int idx = 0;
            while (p + 12 <= end) {
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
            const uint8_t* p = data;
            int idx = 0;
            while (p + 4 <= end) {
                uint32_t len;
                std::memcpy(&len, p, sizeof(len));  // little-endian assumed
                p += 4;
                if (!require(p + len <= end)) return DECODE_ERROR_STR;
                const char* s = reinterpret_cast<const char*>(p);
                out << "  [" << idx++ << "] \"" << std::string(s, s + len) << "\"\n";
                p += len;
            }
            if (!require(p == end)) return DECODE_ERROR_STR;
            break;
        }

        case Type::FIXED_LEN_BYTE_ARRAY: {
            if (!datatype_length.has_value() || datatype_length.value() <= 0 || (adjusted_raw.size() % datatype_length.value()) != 0) {
                return DECODE_ERROR_STR;
            }
            
            int fixed_length = datatype_length.value();
            
            out << "Decoded FIXED_LEN_BYTE_ARRAY (length=" << fixed_length << "):\n";
            size_t element_count = adjusted_raw.size() / fixed_length;
            for (size_t i = 0; i < element_count; ++i) {
                const char* element_start = reinterpret_cast<const char*>(data + i * fixed_length);
                out << "  [" << i << "] \"" << std::string(element_start, fixed_length) << "\"\n";
            }
            break;
        }

        // This is a known type, but passed as "undefined" by the API caller intentionally.
        case Type::UNDEFINED: {
            out << "Decoded UNDEFINED type (raw bytes):\n";
            const char* s = reinterpret_cast<const char*>(data);
            out << "  \"" << std::string(s, s + adjusted_raw.size()) << "\"\n";
            break;
        }

        default:
            return UNSUPPORTED_TYPE_STR;
    }

    return out.str();
}
