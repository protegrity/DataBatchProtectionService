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

#include "decoding_utils.h"
#include "enum_utils.h"
#include <iostream>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <array>

using namespace dbps::external;
using namespace dbps::enum_utils;

int CalculateLevelBytesLength(const std::vector<uint8_t>& raw,
    const std::map<std::string, std::variant<int32_t, bool, std::string>>& encoding_attribs) {
    
    // Helper function to skip V1 RLE level data in raw bytes
    // Returns number of bytes consumed: [4-byte len] + [level bytes indicated by `len`]
    auto SkipV1RLELevel = [&raw](size_t& offset) -> int {
        if (offset + 4 > raw.size()) {
            throw InvalidInputException(
                "Invalid RLE level data: offset + 4 exceeds data size (offset=" + 
                std::to_string(offset) + ", size=" + std::to_string(raw.size()) + ")");
        }
        uint32_t len = *reinterpret_cast<const uint32_t*>(raw.data() + offset);
        if (offset + 4 + len > raw.size()) {
            throw InvalidInputException(
                "Invalid RLE level data: length field overflows (offset=" + 
                std::to_string(offset) + ", len=" + std::to_string(len) + ", size=" + 
                std::to_string(raw.size()) + ")");
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
            throw InvalidInputException(
                "Invalid encoding for DATA_PAGE_V1: repetition_level_encoding=" + rep_encoding + 
                ", definition_level_encoding=" + def_encoding + " (only RLE is expected)");
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
        throw DBPSUnsupportedException("Unsupported page type: " + page_type);
    }

    // Validate that the total level bytes before returning.
    if (total_level_bytes < 0) {
        throw InvalidInputException(
            "Invalid level bytes calculation: negative total_level_bytes=" + std::to_string(total_level_bytes));
    }
    if (total_level_bytes > static_cast<int>(raw.size())) {
        throw InvalidInputException(
            "Invalid level bytes calculation: total_level_bytes=" + std::to_string(total_level_bytes) + 
            " exceeds data size=" + std::to_string(raw.size()));
    }
    return total_level_bytes;
}

LevelAndValueBytes Split(const std::vector<uint8_t>& bytes, int index) {
    LevelAndValueBytes result;

    if (index < 0 || index > static_cast<int>(bytes.size())) {
        throw InvalidInputException("Invalid index for splitting bytes: " + std::to_string(index));
    }
    result.level_bytes = std::vector<uint8_t>(bytes.begin(), bytes.begin() + index);
    result.value_bytes = std::vector<uint8_t>(bytes.begin() + index, bytes.end());

    return result;
}

template<typename T>
std::vector<T> DecodeFixedSizeType(const uint8_t* raw_data, size_t raw_size, const char* name) {
    if ((raw_size % sizeof(T)) != 0) {
        throw InvalidInputException(std::string("Invalid data size for ") + name + " decoding");
    }
    std::vector<T> result;
    const T* v = reinterpret_cast<const T*>(raw_data);
    size_t count = raw_size / sizeof(T);
    result.assign(v, v + count);
    return result;
}

TypedListValues ParseValueBytesIntoTypedList(
    const std::vector<uint8_t>& bytes,
    Type::type datatype,
    const std::optional<int>& datatype_length,
    Format::type format) {
    if (format != Format::PLAIN) {
        throw DBPSUnsupportedException("Unsupported format: " + std::string(to_string(format)));
    }
    switch (datatype) {
        case Type::INT32: {
            return DecodeFixedSizeType<int32_t>(bytes.data(), bytes.size(), "INT32");
        }
        case Type::INT64: {
            return DecodeFixedSizeType<int64_t>(bytes.data(), bytes.size(), "INT64");
        }
        case Type::FLOAT: {
            return DecodeFixedSizeType<float>(bytes.data(), bytes.size(), "FLOAT");
        }
        case Type::DOUBLE: {
            return DecodeFixedSizeType<double>(bytes.data(), bytes.size(), "DOUBLE");
        }
        case Type::INT96: {
            if ((bytes.size() % 12) != 0) {
                throw InvalidInputException("Invalid data size for INT96 decoding");
            }
            std::vector<std::array<uint32_t, 3>> result;
            const uint8_t* p = bytes.data();
            const uint8_t* last_byte = bytes.data() + bytes.size();
            while (p + 12 <= last_byte) {
                std::array<uint32_t, 3> value;
                memcpy(&value[0], p + 0, 4);
                memcpy(&value[1], p + 4, 4);
                memcpy(&value[2], p + 8, 4);
                result.push_back(value);
                p += 12;
            }
            return result;
        }
        case Type::BYTE_ARRAY: {
            std::vector<std::string> result;
            const uint8_t* p = bytes.data();
            const uint8_t* last_byte = bytes.data() + bytes.size();
            while (p + 4 <= last_byte) {
                uint32_t len;
                memcpy(&len, p, sizeof(len));
                p += 4;
                if (p + len > last_byte) {
                    throw InvalidInputException(
                        "Invalid BYTE_ARRAY encoding: length exceeds data bounds");
                }
                const char* s = reinterpret_cast<const char*>(p);
                result.emplace_back(s, len);
                p += len;
            }
            if (p != last_byte) {
                throw InvalidInputException(
                    "Invalid BYTE_ARRAY encoding: unexpected trailing bytes");
            }
            return result;
        }
        case Type::FIXED_LEN_BYTE_ARRAY: {
            if (!datatype_length.has_value() || datatype_length.value() <= 0) {
                throw InvalidInputException(
                    "FIXED_LEN_BYTE_ARRAY requires positive datatype_length");
            }
            int fixed_length = datatype_length.value();
            if ((bytes.size() % fixed_length) != 0) {
                throw InvalidInputException(
                    "Invalid data size for FIXED_LEN_BYTE_ARRAY decoding");
            }
            std::vector<std::string> result;
            size_t element_count = bytes.size() / fixed_length;
            for (size_t i = 0; i < element_count; ++i) {
                const char* element_start = reinterpret_cast<const char*>(
                    bytes.data() + i * fixed_length);
                result.emplace_back(element_start, fixed_length);
            }
            return result;
        }
        case Type::UNDEFINED: {
            std::vector<uint8_t> result;
            const char* s = reinterpret_cast<const char*>(bytes.data());
            result.assign(s, s + bytes.size());
            return result;
        }
        default: {
            throw DBPSUnsupportedException(
                "Unsupported datatype: " + std::string(to_string(datatype)));
        }
    }
}

template<typename T>
const char* GetTypeName() {
    if constexpr (std::is_same_v<T, std::vector<int32_t>>) return "INT32";
    else if constexpr (std::is_same_v<T, std::vector<int64_t>>) return "INT64";
    else if constexpr (std::is_same_v<T, std::vector<float>>) return "FLOAT";
    else if constexpr (std::is_same_v<T, std::vector<double>>) return "DOUBLE";
    else if constexpr (std::is_same_v<T, std::vector<std::array<uint32_t, 3>>>) return "INT96";
    else if constexpr (std::is_same_v<T, std::vector<std::string>>) 
      return "string (BYTE_ARRAY/FIXED_LEN_BYTE_ARRAY)";
    else if constexpr (std::is_same_v<T, std::vector<uint8_t>>) return "UNDEFINED (raw bytes)";
    else if constexpr (std::is_same_v<T, std::monostate>) return "empty/error";
    else return "unknown";
}

std::string PrintTypedList(const TypedListValues& list) {
    std::ostringstream out;
    
    std::visit([&out](auto&& values) {
        using T = std::decay_t<decltype(values)>;
        
        if constexpr (std::is_same_v<T, std::monostate>) {
            out << "Empty/error state\n";
        }
        else if constexpr (std::is_same_v<T, std::vector<std::array<uint32_t, 3>>>) {
            // Special case for INT96 - [lo, mid, hi] format
            out << "Decoded INT96 values ([lo, mid, hi] 32-bit words):\n";
            for (size_t i = 0; i < values.size(); ++i) {
                out << "  [" << i << "] [" << values[i][0] << ", " 
                    << values[i][1] << ", " << values[i][2] << "]\n";
            }
        }
        else if constexpr (std::is_same_v<T, std::vector<uint8_t>>) {
            // Special case for UNDEFINED - raw bytes as hex
            out << "Decoded UNDEFINED type (raw bytes):\n";
            out << "  Hex: ";
            for (size_t i = 0; i < values.size(); ++i) {
                out << std::hex << std::setw(2) << std::setfill('0') 
                    << static_cast<int>(values[i]);
                if (i < values.size() - 1) out << " ";
            }
            out << std::dec << "\n";  // Reset to decimal
            
            // Also show as string if printable
            out << "  String: \"";
            for (uint8_t byte : values) {
                if (byte >= 32 && byte < 127) {
                    out << static_cast<char>(byte);
                } else {
                    out << ".";
                }
            }
            out << "\"\n";
        }
        else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
            // String values with quotes and the length of the string.
            out << "Decoded " << GetTypeName<T>() << " values:\n";
            for (size_t i = 0; i < values.size(); ++i) {
                out << "  [" << i << "] \"" << values[i] << "\" (length: " << values[i].size() << ")\n";
            }
        }
        else {
            // Generic case for numeric types (int32, int64, float, double)
            out << "Decoded " << GetTypeName<T>() << " values:\n";
            for (size_t i = 0; i < values.size(); ++i) {
                out << "  [" << i << "] " << values[i] << "\n";
            }
        }
    }, list);
    
    return out.str();
}
