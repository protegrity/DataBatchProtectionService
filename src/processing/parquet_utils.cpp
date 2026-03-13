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
#include "typed_buffer_values.h"
#include <cstring>
#include <iostream>

using namespace dbps::external;
using namespace dbps::enum_utils;
using namespace dbps::compression;
using namespace dbps::processing;

// -----------------------------------------------------------------------------
// Helper functions for Parquet DATA_PAGE_V1 definition level bytes parsing to count present values.
// -----------------------------------------------------------------------------

// Decodes one unsigned LEB128 (base-128 varint) run header from `bytes`,
// starting at `offset`, and advances `offset` past the decoded header bytes.
//
// A "run header" is a variable-length encoded integer that indicates the length of a run.
//
// In Parquet V1 hybrid RLE/bit-packed streams, this run header indicates:
// - RLE run when (header & 1) == 0, with run_length = header >> 1
// - Bit-packed run when (header & 1) == 1, with num_groups = header >> 1
//   and run_length = num_groups * 8 values
//
// This is used by V1 definition-level decoding to iterate runs and compute
// the count of present (non-null) values in nullable data pages.
//
uint32_t ReadV1RunHeaderUleb128(tcb::span<const uint8_t> bytes, size_t& offset) {
    uint32_t value = 0;
    int shift = 0;
    while (true) {
        if (offset >= bytes.size()) {
            throw InvalidInputException("Invalid DATA_PAGE_V1 level stream: truncated varint header");
        }
        uint8_t b = bytes[offset++];
        value |= static_cast<uint32_t>(b & 0x7F) << shift;
        if ((b & 0x80) == 0) {
            return value;
        }
        shift += 7;
        if (shift > 28) {
            throw InvalidInputException("Invalid DATA_PAGE_V1 level stream: varint header too large");
        }
    }
}

// Decodes a DATA_PAGE_V1 definition-level payload (hybrid RLE/bit-packed) and
// returns the number of present (non-null) values in the page.
//
// Inputs:
// - def_payload: bytes of the V1 definition-level stream payload only
//   (without the outer [u32 length] prefix).
// - num_values: total number of logical values in the page (includes nulls).
// - max_def_level: maximum definition level for the column in this page.
//
// Output:
// - present_count = number of decoded definition levels equal to max_def_level.
//
size_t CountPresentFromDefinitionLevelsV1(tcb::span<const uint8_t> def_payload, int32_t num_values, int32_t max_def_level) {
    if (num_values < 0) {
        throw InvalidInputException("Invalid V1 definition levels: num_values must be non-negative, got " + 
            std::to_string(num_values));
    }
    if (max_def_level <= 0) {
        throw InvalidInputException("Invalid V1 definition levels: max_def_level must be positive, got " + 
            std::to_string(max_def_level));
    }

    // Definition level bit width is ceil(log2(max_def_level + 1)).
    // Computes the minimum number of bits needed to represent definition levels from 0..max_def_level.
    int bit_width = 0;
    uint32_t def_level_domain = static_cast<uint32_t>(max_def_level);
    while (def_level_domain > 0) {
        ++bit_width;
        def_level_domain >>= 1;
    }
    if (bit_width <= 0) {
        throw InvalidInputException("Invalid V1 definition levels: computed bit_width must be positive");
    }

    size_t present_count = 0;
    size_t decoded_values = 0;
    size_t def_offset = 0;

    // Hybrid RLE/bit-packed decode loop.
    while (decoded_values < static_cast<size_t>(num_values)) {
        uint32_t header = ReadV1RunHeaderUleb128(def_payload, def_offset);

        if ((header & 1u) == 0u) {
            // RLE run: header = (run_len << 1), then repeated value in ceil(bit_width/8) bytes.
            const size_t run_len = static_cast<size_t>(header >> 1);
            const size_t remaining = static_cast<size_t>(num_values) - decoded_values;
            if (run_len == 0 || run_len > remaining) {
                throw InvalidInputException("Invalid DATA_PAGE_V1 definition levels: invalid RLE run length");
            }

            const size_t byte_width = static_cast<size_t>((bit_width + 7) / 8);
            if (def_offset + byte_width > def_payload.size()) {
                throw InvalidInputException("Invalid V1 definition levels: truncated RLE run value");
            }

            uint32_t level = 0;
            for (size_t i = 0; i < byte_width; ++i) {
                level |= static_cast<uint32_t>(def_payload[def_offset + i]) << (8 * i);
            }
            def_offset += byte_width;
            if (level > static_cast<uint32_t>(max_def_level)) {
                throw InvalidInputException("Invalid DATA_PAGE_V1 definition levels: decoded level exceeds max_def_level");
            }

            if (level == static_cast<uint32_t>(max_def_level)) {
                present_count += run_len;
            }
            decoded_values += run_len;
        } else {
            // Bit-packed run: header = (num_groups << 1) | 1, each group has 8 values.
            const size_t num_groups = static_cast<size_t>(header >> 1);
            const size_t run_len = num_groups * 8;
            const size_t remaining = static_cast<size_t>(num_values) - decoded_values;
            if (num_groups == 0) {
                throw InvalidInputException("Invalid DATA_PAGE_V1 definition levels: invalid bit-packed run length");
            }

            const size_t total_bits = run_len * static_cast<size_t>(bit_width);
            const size_t byte_len = (total_bits + 7) / 8;
            if (def_offset + byte_len > def_payload.size()) {
                throw InvalidInputException("Invalid DATA_PAGE_V1 definition levels: truncated bit-packed run payload");
            }
            auto packed = tcb::span<const uint8_t>(def_payload.data() + def_offset, byte_len);
            def_offset += byte_len;

            auto ReadPacked = [&](size_t bit_offset) -> uint32_t {
                uint32_t v = 0;
                for (int b = 0; b < bit_width; ++b) {
                    size_t abs_bit = bit_offset + static_cast<size_t>(b);
                    size_t byte_index = abs_bit / 8;
                    size_t bit_index = abs_bit % 8;
                    uint8_t bit = static_cast<uint8_t>((packed[byte_index] >> bit_index) & 0x01);
                    v |= static_cast<uint32_t>(bit) << b;
                }
                return v;
            };

            // A final bit-packed run may include padded trailing values to complete
            // 8-value groups. Decode only the logical values still remaining.
            const size_t values_to_decode = std::min(run_len, remaining);
            for (size_t i = 0; i < values_to_decode; ++i) {
                uint32_t level = ReadPacked(i * static_cast<size_t>(bit_width));
                if (level > static_cast<uint32_t>(max_def_level)) {
                    throw InvalidInputException("Invalid DATA_PAGE_V1 definition levels: decoded level exceeds max_def_level");
                }
                if (level == static_cast<uint32_t>(max_def_level)) {
                    ++present_count;
                }
            }
            decoded_values += values_to_decode;
        }
    }
    if (def_offset != def_payload.size()) {
        throw InvalidInputException("Invalid DATA_PAGE_V1 definition levels: trailing bytes after decoding");
    }
    return present_count;
}

// -----------------------------------------------------------------------------
// Helper functions to read/split DATA_PAGE_V1 level bytes -- Read length-prefixed level bytes
// -----------------------------------------------------------------------------

// Function to read a length-prefixed payload from the level bytes.
tcb::span<const uint8_t> ReadV1LengthPrefixedPayload(tcb::span<const uint8_t> bytes, size_t& offset) {
    if (offset + 4 > bytes.size()) {
        throw InvalidInputException(
            "Invalid Parquet DATA_PAGE_V1 level bytes: missing 4-byte length prefix");
    }
    uint32_t len = read_u32_le(bytes, offset);
    const size_t payload_offset = offset + 4;
    if (len > bytes.size() - payload_offset) {
        throw InvalidInputException(
            "Invalid Parquet DATA_PAGE_V1 level bytes: length-prefixed block exceeds bounds");
    }
    offset = payload_offset + static_cast<size_t>(len);
    return tcb::span<const uint8_t>(bytes.data() + payload_offset, static_cast<size_t>(len));
}

// Function to skip the repetition levels bytes and return the definition levels bytes payload.
tcb::span<const uint8_t> ReadDefinitionLevelBytesV1(tcb::span<const uint8_t> level_bytes, int32_t max_rep_level) {
    // V1 level bytes are [rep_levels?][def_levels], each as [u32 len][payload].
    size_t level_offset = 0;

    // Skip the repetition levels bytes if any.
    if (max_rep_level > 0) {
        (void) ReadV1LengthPrefixedPayload(level_bytes, level_offset);
    }

    // Read the definition levels bytes.
    auto def_payload = ReadV1LengthPrefixedPayload(level_bytes, level_offset);
    if (level_offset != level_bytes.size()) {
        throw InvalidInputException("Invalid Parquet DATA_PAGE_V1 level bytes: trailing bytes after definition levels block");
    }
    return def_payload;
}

// -----------------------------------------------------------------------------
// Helper function to calculate level bytes length
// -----------------------------------------------------------------------------

int CalculateLevelBytesLength(tcb::span<const uint8_t> raw,
    const AttributesMap& encoding_attribs) {

    // Get page_type from the converted attributes
    const std::string& page_type = std::get<std::string>(encoding_attribs.at("page_type"));
    int total_level_bytes = 0;

    if (page_type == "DATA_PAGE_V2") {
        // For DATA_PAGE_V2: sum of definition and repetition level byte lengths
        int32_t def_level_length = std::get<int32_t>(encoding_attribs.at("page_v2_definition_levels_byte_length"));
        int32_t rep_level_length = std::get<int32_t>(encoding_attribs.at("page_v2_repetition_levels_byte_length"));
        total_level_bytes = def_level_length + rep_level_length;
    } else if (page_type == "DATA_PAGE_V1") {
        // Check that encoding types are RLE (instead of BIT_PACKED which is deprecated)
        const std::string& rep_encoding = std::get<std::string>(encoding_attribs.at("page_v1_repetition_level_encoding"));
        const std::string& def_encoding = std::get<std::string>(encoding_attribs.at("page_v1_definition_level_encoding"));
        if (rep_encoding != "RLE" || def_encoding != "RLE") {
            throw InvalidInputException(
                "Invalid encoding for DATA_PAGE_V1: repetition_level_encoding=" + rep_encoding + 
                ", definition_level_encoding=" + def_encoding + " (only RLE is expected)");
        }

        // Read and skip the repetition/definition level bytes to calculate the final offset where
        // the level bytes end and the value bytes start.
        // - If max_rep_level > 0, there are repetition levels bytes. Same for definition levels.
        int32_t max_rep_level = std::get<int32_t>(encoding_attribs.at("data_page_max_repetition_level"));
        int32_t max_def_level = std::get<int32_t>(encoding_attribs.at("data_page_max_definition_level"));
        size_t offset = 0;
        if (max_rep_level > 0) {
            size_t start_offset = offset;
            (void) ReadV1LengthPrefixedPayload(raw, offset);
            total_level_bytes += static_cast<int>(offset - start_offset);
        }
        if (max_def_level > 0) {
            size_t start_offset = offset;
            (void) ReadV1LengthPrefixedPayload(raw, offset);
            total_level_bytes += static_cast<int>(offset - start_offset);
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

// -----------------------------------------------------------------------------
// Public functions to process Parquet formatted Dictionary and Data pages
// -----------------------------------------------------------------------------

LevelAndValueBytes DecompressAndSplit(
    tcb::span<const uint8_t> plaintext,
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

        // For DATA_PAGE_V1, calculate num_elements by parsing the level bytes.
        size_t num_elements = 0;
        const int32_t num_values = std::get<int32_t>(encoding_attributes.at("data_page_num_values"));
        int32_t max_def_level = std::get<int32_t>(encoding_attributes.at("data_page_max_definition_level"));
        int32_t max_rep_level = std::get<int32_t>(encoding_attributes.at("data_page_max_repetition_level"));
        if (max_def_level == 0) {
            // All values are present in the value bytes section.
            num_elements = static_cast<size_t>(num_values);
        }
        // If max_def_level > 0, there are definition levels bytes. So parse it and count the present values.
        else {
            auto def_bytes_payload = ReadDefinitionLevelBytesV1(level_bytes, max_rep_level);
            num_elements = CountPresentFromDefinitionLevelsV1(def_bytes_payload, num_values, max_def_level);
        }

        return LevelAndValueBytes{std::move(level_bytes), std::move(value_bytes), num_elements};
    }

    // On DATA_PAGE_V2, only the value bytes are compressed.
    // So the split of level and value byte requires to
    // (1) calculate length of level bytes, (2) split into level, (3) decompress only the value bytes.
    if (page_type == "DATA_PAGE_V2") {
        int leading_bytes_to_strip = CalculateLevelBytesLength(
            plaintext, encoding_attributes);
        auto [level_bytes_span, compressed_value_bytes_span] = Split(plaintext, leading_bytes_to_strip);
        std::vector<uint8_t> level_bytes(level_bytes_span.begin(), level_bytes_span.end());

        bool page_v2_is_compressed = std::get<bool>(
            encoding_attributes.at("page_v2_is_compressed"));
        std::vector<uint8_t> value_bytes;
        if (page_v2_is_compressed) {
            value_bytes = Decompress(compressed_value_bytes_span, compression);
        } else {
            value_bytes = std::vector<uint8_t>(compressed_value_bytes_span.begin(), compressed_value_bytes_span.end());
        }

        // For DATA_PAGE_V2, get num_elements from num_values and num_nulls in encoding_attributes.
        int32_t num_values = std::get<int32_t>(encoding_attributes.at("data_page_num_values"));
        int32_t num_nulls = std::get<int32_t>(encoding_attributes.at("page_v2_num_nulls"));
        if (num_nulls > num_values) {
            throw InvalidInputException(
                "Invalid num_nulls: " + std::to_string(num_nulls) + " > num_values: " +
                std::to_string(num_values) + " in DATA_PAGE_V2 encoding attributes");
        }
        size_t num_elements = static_cast<size_t>(num_values - num_nulls);

        return LevelAndValueBytes{std::move(level_bytes), std::move(value_bytes), num_elements};
    }

    // DICTIONARY_PAGE has no level bytes.
    if (page_type == "DICTIONARY_PAGE") {
        auto level_bytes = std::vector<uint8_t>();
        auto value_bytes = Decompress(plaintext, compression);
        size_t num_elements = static_cast<size_t>( std::get<int32_t>(encoding_attributes.at("dict_page_num_values")));
        return LevelAndValueBytes{std::move(level_bytes), std::move(value_bytes), num_elements};
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

// -----------------------------------------------------------------------------
// Public functions to build Parquet formatted value bytes into TypedValuesBuffer
// -----------------------------------------------------------------------------

TypedValuesBuffer ReinterpretValueBytesAsTypedValuesBuffer(
    tcb::span<const uint8_t> value_bytes,
    size_t num_elements,
    Type::type datatype,
    const std::optional<int>& datatype_length,
    Encoding::type encoding) {

    if (encoding == Encoding::RLE_DICTIONARY) {
        throw DBPSUnsupportedException(
            "Unsupported encoding: RLE_DICTIONARY is not supported for per-value operations "
            "since values are not present in the data, only references to them.");
    }

    if (encoding != Encoding::PLAIN) {
        throw DBPSUnsupportedException(
            "On ReinterpretValueBytesAsTypedValuesBuffer, unsupported encoding: "
            + std::string(to_string(encoding)));
    }

    if (datatype == Type::BOOLEAN) {
        throw DBPSUnsupportedException("On ReinterpretValueBytesAsTypedValuesBuffer, BOOLEAN datatype "
            "values are bit-encoded and not expanded as bytes, so BOOLEAN is not supported.");
    }

    switch (datatype) {
        case Type::INT32:
            return TypedBufferI32{value_bytes, num_elements};
        case Type::INT64:
            return TypedBufferI64{value_bytes, num_elements};
        case Type::FLOAT:
            return TypedBufferFloat{value_bytes, num_elements};
        case Type::DOUBLE:
            return TypedBufferDouble{value_bytes, num_elements};
        case Type::INT96:
            return TypedBufferInt96{value_bytes, num_elements};
        case Type::FIXED_LEN_BYTE_ARRAY: {
            if (!datatype_length.has_value() || datatype_length.value() <= 0) {
                throw InvalidInputException("FIXED_LEN_BYTE_ARRAY requires a positive datatype_length");
            }
            return TypedBufferRawBytesFixedSized{
                value_bytes, num_elements, 0, RawBytesFixedSizedCodec{static_cast<size_t>(datatype_length.value())}};
        }
        case Type::BYTE_ARRAY:
            return TypedBufferRawBytesVariableSized{value_bytes, num_elements};
        default:
            throw InvalidInputException(
                "Invalid datatype: " + std::string(to_string(datatype)));
    }
}

std::vector<uint8_t> GetTypedValuesBufferAsValueBytes(TypedValuesBuffer&& buffer) {
    // std::visit is needed to unwrap the variant. TypedValuesBuffer could be of different ByteBuffer types,
    // so the indirection is needed to call FinalizeAndTakeBuffer() on the correct type. In practice, this is the same for all.
    return std::visit([](auto& buf) -> std::vector<uint8_t> {
        return buf.FinalizeAndTakeBuffer();
    }, buffer);
}

// -----------------------------------------------------------------------------
