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

#include "parquet_utils.h"
#include "enum_utils.h"
#include "compression_utils.h"
#include <cstring>
#include <iostream>

using namespace dbps::external;
using namespace dbps::enum_utils;
using namespace dbps::compression;

int CalculateLevelBytesLength(const std::vector<uint8_t>& raw,
    const AttributesMap& encoding_attribs) {
    
    // Helper function to skip V1 RLE level data in raw bytes
    // Returns number of bytes consumed: [4-byte len] + [level bytes indicated by `len`]
    auto SkipV1RLELevel = [&raw](size_t& offset) -> int {
        if (offset + 4 > raw.size()) {
            throw InvalidInputException(
                "Invalid RLE level data: offset + 4 exceeds data size (offset=" + 
                std::to_string(offset) + ", size=" + std::to_string(raw.size()) + ")");
        }
        uint32_t len = read_u32_le(raw, offset);
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
        // TODO(Issue 183): Remove unnecessary printouts in this function.
        std::cout << "CalculateLevelBytesLength DATA_PAGE_V2: total_level_bytes="
                  << total_level_bytes << std::endl;
        
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
            std::cout << "CalculateLevelBytesLength DATA_PAGE_V1: repetition level bytes skipped="
                      << bytes_skipped << std::endl;
        }
        if (max_def_level > 0) {
            int bytes_skipped = SkipV1RLELevel(offset);
            total_level_bytes += bytes_skipped;
            std::cout << "CalculateLevelBytesLength DATA_PAGE_V1: definition level bytes skipped="
                      << bytes_skipped << std::endl;
        }

    } else if (page_type == "DICTIONARY_PAGE") {
        // DICTIONARY_PAGE has no level bytes
        total_level_bytes = 0;

    } else {
        // Invalid page type
        throw InvalidInputException("Invalid page type: " + page_type);
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

inline static size_t GetFixedElemSizeOrThrow(Type::type datatype, const std::optional<int>& datatype_length) {
    switch (datatype) {
        case Type::INT32:
        case Type::FLOAT:
            return 4;
        case Type::INT64:
        case Type::DOUBLE:
            return 8;
        case Type::INT96:
            // INT96 is three little-endian uint32 words laid out consecutively (lo, mid, hi).
            return 12;
        case Type::FIXED_LEN_BYTE_ARRAY: {
            if (!datatype_length.has_value() || datatype_length.value() <= 0) {
                throw InvalidInputException(
                    "FIXED_LEN_BYTE_ARRAY requires a positive datatype_length");
            }
            return static_cast<size_t>(datatype_length.value());
        }
        case Type::UNDEFINED:
            return 1;
        case Type::BYTE_ARRAY:
            throw InvalidInputException("BYTE_ARRAY is variable-length; not fixed-size");
        default:
            throw InvalidInputException(
                "Invalid datatype. Only fixed-size types are supported: " + std::string(to_string(datatype)));
    }
}

std::vector<RawValueBytes> SliceValueBytesIntoRawBytes(
    const std::vector<uint8_t>& bytes,
    Type::type datatype,
    const std::optional<int>& datatype_length,
    Format::type format) {

    // RLE_DICTIONARY is not supported for per-value operations since the values themselves are not present in the data,
    // only references to them.
    if (format == Format::RLE_DICTIONARY) {
        throw DBPSUnsupportedException("Unsupported format: RLE_DICTIONARY is not supported for per-value operations");
    }

    if (format != Format::PLAIN) {
        throw DBPSUnsupportedException("On SliceValueBytesIntoRawBytes, unsupported format: " + std::string(to_string(format)));
    }

    // Variable-length BYTE_ARRAY: parse [4-byte len][bytes...] elements in order.
    // This is the Parquet specific encoding for BYTE_ARRAY.
    if (datatype == Type::BYTE_ARRAY) {
        std::vector<RawValueBytes> out;
        const uint8_t* p = bytes.data();
        const uint8_t* last = bytes.data() + bytes.size();
        while (p + 4 <= last) {
            uint32_t len = 0;
            std::memcpy(&len, p, sizeof(len)); // little-endian length
            p += 4;
            if (p + len > last) {
                throw InvalidInputException(
                    "Invalid BYTE_ARRAY encoding: length exceeds data bounds");
            }
            out.emplace_back(p, p + len);
            p += len;
        }
        if (p != last) {
            throw InvalidInputException("Invalid BYTE_ARRAY encoding: trailing bytes remain");
        }
        return out;
    }

    // Fixed-size types: slice into raw value bytes in order.
    const size_t elem_size = GetFixedElemSizeOrThrow(datatype, datatype_length);

    // Validate that the input size is divisible by the element size
    if ((bytes.size() % elem_size) != 0) {
        throw InvalidInputException("Input size not divisible by element width");
    }

    // Slice the input bytes into raw value bytes
    const size_t count = bytes.size() / elem_size;
    std::vector<RawValueBytes> out;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const auto begin = bytes.begin() + static_cast<std::ptrdiff_t>(i * elem_size);
        out.emplace_back(begin, begin + static_cast<std::ptrdiff_t>(elem_size));
    }
    return out;
}

std::vector<uint8_t> CombineRawBytesIntoValueBytes(
    const std::vector<RawValueBytes>& elements,
    Type::type datatype,
    const std::optional<int>& datatype_length,
    Format::type format) {

    // RLE_DICTIONARY is not supported for per-value operations since the values themselves are not present in the data,
    // only references to them.
    if (format == Format::RLE_DICTIONARY) {
        throw DBPSUnsupportedException("Unsupported format: RLE_DICTIONARY is not supported for per-value operations");
    }

    if (format != Format::PLAIN) {
        throw DBPSUnsupportedException("On CombineRawBytesIntoValueBytes, unsupported format: " + std::string(to_string(format)));
    }

    if (datatype == Type::BYTE_ARRAY) {
        std::vector<uint8_t> out;
        size_t total = 0;
        for (const auto& v : elements) {
            total += 4 + v.size();
        }
        out.reserve(total);
        for (const auto& v : elements) {
            append_u32_le(out, static_cast<uint32_t>(v.size()));
            out.insert(out.end(), v.begin(), v.end());
        }
        return out;
    }

    const size_t elem_size = GetFixedElemSizeOrThrow(datatype, datatype_length);

    for (size_t i = 0; i < elements.size(); ++i) {
        if (elements[i].size() != elem_size) {
            throw InvalidInputException("Element size mismatch for fixed-size datatype");
        }
    }

    std::vector<uint8_t> out;
    out.reserve(elem_size * elements.size());
    for (const auto& v : elements) {
        out.insert(out.end(), v.begin(), v.end());
    }
    return out;
}

LevelAndValueBytes DecompressAndSplit(
    const std::vector<uint8_t>& plaintext,
    CompressionCodec::type compression,
    const AttributesMap& encoding_attributes) {

    // Get the page type from the encoding attributes.
    auto page_type = std::get<std::string>(encoding_attributes.at("page_type"));

    // On DATA_PAGE_V1, the whole payload is compressed.
    // So the split of level and value byte requires to
    // (1) decompress the whole payload, (2) calculate length of level bytes, (3) split into level and value bytes.
    if (page_type == "DATA_PAGE_V1") {
        auto decompressed_bytes = Decompress(plaintext, compression);
        int leading_bytes_to_strip = CalculateLevelBytesLength(
            decompressed_bytes, encoding_attributes);
        auto [level_bytes, value_bytes] = Split(decompressed_bytes, leading_bytes_to_strip);
        return LevelAndValueBytes{level_bytes, value_bytes};
    }

    // On DATA_PAGE_V2, only the value bytes are compressed.
    // So the split of level and value byte requires to
    // (1) calculate length of level bytes, (2) split into level, (3) decompress only the value bytes.
    if (page_type == "DATA_PAGE_V2") {
        int leading_bytes_to_strip = CalculateLevelBytesLength(
            plaintext, encoding_attributes);
        auto [level_bytes, compressed_value_bytes] = Split(plaintext, leading_bytes_to_strip);

        bool page_v2_is_compressed = std::get<bool>(
            encoding_attributes.at("page_v2_is_compressed"));
        std::vector<uint8_t> value_bytes;
        if (page_v2_is_compressed) {
            value_bytes = Decompress(compressed_value_bytes, compression);
        } else {
            value_bytes = compressed_value_bytes;
        }
        return LevelAndValueBytes{level_bytes, value_bytes};
    }

    // DICTIONARY_PAGE has no level bytes.
    if (page_type == "DICTIONARY_PAGE") {
        auto level_bytes = std::vector<uint8_t>();
        auto value_bytes = Decompress(plaintext, compression);
        return LevelAndValueBytes{level_bytes, value_bytes};
    }

    throw InvalidInputException("Unexpected page type: " + page_type);
}

std::vector<uint8_t> CompressAndJoin(
    const std::vector<uint8_t>& level_bytes,
    const std::vector<uint8_t>& value_bytes,
    CompressionCodec::type compression,
    const AttributesMap& encoding_attributes) {

    // Get the page type from the encoding attributes.
    const auto& page_type = std::get<std::string>(encoding_attributes.at("page_type"));
    
    // Check that the calculated level bytes size == the size of the actual level bytes.
    int expected_level_bytes = CalculateLevelBytesLength(level_bytes, encoding_attributes);
    if (static_cast<size_t>(expected_level_bytes) != level_bytes.size()) {
        throw InvalidInputException("Level bytes size does not match encoding attributes");
    }

    if (page_type == "DATA_PAGE_V1") {
        auto joined = Join(level_bytes, value_bytes);
        return Compress(joined, compression);
    }

    if (page_type == "DATA_PAGE_V2") {
        bool page_v2_is_compressed =
            std::get<bool>(encoding_attributes.at("page_v2_is_compressed"));
        if (page_v2_is_compressed) {
            auto compressed_values = Compress(value_bytes, compression);
            return Join(level_bytes, compressed_values);
        } else {
            return Join(level_bytes, value_bytes);
        }
    }

    // DICTIONARY_PAGE has no level bytes.
    if (page_type == "DICTIONARY_PAGE") {
        return Compress(value_bytes, compression);
    }

    throw InvalidInputException("Unexpected page type: " + page_type);
}

TypedListValues ParseValueBytesIntoTypedList(
    const std::vector<uint8_t>& bytes,
    Type::type datatype,
    const std::optional<int>& datatype_length,
    Format::type format) {
    std::vector<RawValueBytes> raw_values =
        SliceValueBytesIntoRawBytes(bytes, datatype, datatype_length, format);
    return BuildTypedListFromRawBytes(datatype, raw_values);
}

std::vector<uint8_t> GetTypedListAsValueBytes(
    const TypedListValues& list,
    Type::type datatype,
    const std::optional<int>& datatype_length,
    Format::type format) {
    std::vector<RawValueBytes> raw_values = BuildRawBytesFromTypedListValues(list);
    return CombineRawBytesIntoValueBytes(raw_values, datatype, datatype_length, format);
}
