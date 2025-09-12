#pragma once

#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include "enums.h"

/**
 * Decodes raw binary data into a human-readable string for debugging/logging.
 * Returns "decode error" on failure or "unsupported type" for unimplemented types.
 */
std::string PrintPlainDecoded(const std::vector<uint8_t>& raw, dbps::external::Type::type physical_type) {
    static constexpr const char* DECODE_ERROR_STR = "Unknown encoding";
    static constexpr const char* UNSUPPORTED_TYPE_STR = "Unsupported type";

    using Type = dbps::external::Type;

    auto require = [&](bool cond) -> bool { return cond; };

    const uint8_t* data = raw.data();
    const uint8_t* end  = data + raw.size();

    std::ostringstream out;

    switch (physical_type) {
        case Type::INT32: {
            if (!require((raw.size() % sizeof(int32_t)) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded INT32 values:\n";
            const int32_t* v = reinterpret_cast<const int32_t*>(data);
            size_t count = raw.size() / sizeof(int32_t);
            for (size_t i = 0; i < count; ++i) { 
                out << "  [" << i << "] " << v[i] << "\n"; 
            }
            break;
        }

        case Type::INT64: {
            if (!require((raw.size() % sizeof(int64_t)) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded INT64 values:\n";
            const int64_t* v = reinterpret_cast<const int64_t*>(data);
            size_t count = raw.size() / sizeof(int64_t);
            for (size_t i = 0; i < count; ++i) { 
                out << "  [" << i << "] " << v[i] << "\n"; 
            }
            break;
        }

        case Type::FLOAT: {
            if (!require((raw.size() % sizeof(float)) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded FLOAT values:\n";
            const float* v = reinterpret_cast<const float*>(data);
            size_t count = raw.size() / sizeof(float);
            for (size_t i = 0; i < count; ++i) { 
                out << "  [" << i << "] " << v[i] << "\n"; 
            }
            break;
        }

        case Type::DOUBLE: {
            if (!require((raw.size() % sizeof(double)) == 0))
                return DECODE_ERROR_STR;
            out << "Decoded DOUBLE values:\n";
            const double* v = reinterpret_cast<const double*>(data);
            size_t count = raw.size() / sizeof(double);
            for (size_t i = 0; i < count; ++i) { 
                out << "  [" << i << "] " << v[i] << "\n"; 
            }
            break;
        }

        case Type::INT96: {
            if (!require((raw.size() % 12) == 0))
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

        // TODO: Implement FIXED_LEN_BYTE_ARRAY properly.  Currently, it just prints the raw data as a string.
        case Type::FIXED_LEN_BYTE_ARRAY: {
            out << "Decoded FIXED_LEN_BYTE_ARRAY:\n";
            const char* s = reinterpret_cast<const char*>(data);
            out << "  \"" << std::string(s, s + raw.size()) << "\"\n";
            break;
        }

        case Type::UNDEFINED: {
            out << "Decoded UNDEFINED type (raw bytes):\n";
            const char* s = reinterpret_cast<const char*>(data);
            out << "  \"" << std::string(s, s + raw.size()) << "\"\n";
            break;
        }

        default:
            return UNSUPPORTED_TYPE_STR;
    }

    return out.str();
}
