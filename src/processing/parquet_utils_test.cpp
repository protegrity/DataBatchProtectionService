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
#include "../common/exceptions.h"
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <map>
#include <variant>
#include <gtest/gtest.h>
#include "../common/bytes_utils.h"
#include "compression_utils.h"

using namespace dbps::external;
using namespace dbps::compression;
using namespace dbps::processing;

// -----------------------------------------------------------------------------
// Helper functions to generate Parquet DATA_PAGE_V1 level bytes payloads for testing.
// -----------------------------------------------------------------------------

namespace {

std::vector<uint8_t> EncodeUleb128(uint32_t value) {
    std::vector<uint8_t> out;
    do {
        uint8_t byte = static_cast<uint8_t>(value & 0x7F);
        value >>= 7;
        if (value != 0) {
            byte |= 0x80;
        }
        out.push_back(byte);
    } while (value != 0);
    return out;
}

std::vector<uint8_t> MakeRleDefPayload(uint32_t run_len, uint32_t level, int bit_width) {
    std::vector<uint8_t> out = EncodeUleb128(run_len << 1);  // RLE run
    const size_t byte_width = static_cast<size_t>((bit_width + 7) / 8);
    for (size_t i = 0; i < byte_width; ++i) {
        out.push_back(static_cast<uint8_t>((level >> (8 * i)) & 0xFF));
    }
    return out;
}

std::vector<uint8_t> PackBitPackedLevels(
    const std::vector<uint32_t>& levels,
    int bit_width) {
    const size_t total_bits = levels.size() * static_cast<size_t>(bit_width);
    std::vector<uint8_t> out((total_bits + 7) / 8, 0);
    size_t bit_offset = 0;
    for (uint32_t level : levels) {
        for (int b = 0; b < bit_width; ++b) {
            uint8_t bit = static_cast<uint8_t>((level >> b) & 0x01);
            size_t abs_bit = bit_offset + static_cast<size_t>(b);
            out[abs_bit / 8] |= static_cast<uint8_t>(bit << (abs_bit % 8));
        }
        bit_offset += static_cast<size_t>(bit_width);
    }
    return out;
}

std::vector<uint8_t> MakeBitPackedDefPayload(
    const std::vector<uint32_t>& levels,
    int bit_width) {
    EXPECT_EQ(levels.size() % 8, 0u);
    const uint32_t num_groups = static_cast<uint32_t>(levels.size() / 8);
    std::vector<uint8_t> out = EncodeUleb128((num_groups << 1) | 1u);  // bit-packed run
    auto packed = PackBitPackedLevels(levels, bit_width);
    out.insert(out.end(), packed.begin(), packed.end());
    return out;
}

std::vector<uint8_t> WrapLengthPrefixed(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> out;
    append_u32_le(out, static_cast<uint32_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

}  // namespace

// -----------------------------------------------------------------------------
// Tests for CalculateLevelBytesLength function.
// -----------------------------------------------------------------------------

TEST(ParquetUtils, CalculateLevelBytesLength_DATA_PAGE_V2) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_definition_level", int32_t(2)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"page_v2_definition_levels_byte_length", int32_t(1)},
        {"page_v2_repetition_levels_byte_length", int32_t(3)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", false}
    };
    int result = CalculateLevelBytesLength(raw, attribs);
    EXPECT_EQ(4, result); // 1 + 3 
}

TEST(ParquetUtils, CalculateLevelBytesLength_DICTIONARY_PAGE) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    AttributesMap attribs = {
        {"page_type", std::string("DICTIONARY_PAGE")}
    };
    int result = CalculateLevelBytesLength(raw, attribs);
    EXPECT_EQ(0, result);
}

TEST(ParquetUtils, CalculateLevelBytesLength_DATA_PAGE_V1_NoLevels) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"data_page_max_definition_level", int32_t(0)},
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };
    int result = CalculateLevelBytesLength(raw, attribs);
    EXPECT_EQ(0, result);
}

TEST(ParquetUtils, CalculateLevelBytesLength_DATA_PAGE_V1_WithLevels) {
    std::vector<uint8_t> raw;

    // First RLE structure: 4-byte length + 8 bytes of data
    uint32_t len1 = 8;
    raw.resize(raw.size() + sizeof(uint32_t));
    std::memcpy(raw.data() + raw.size() - sizeof(uint32_t), &len1, sizeof(uint32_t));
    raw.insert(raw.end(), {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});

    // Second RLE structure: 4-byte length + 12 bytes of data  
    uint32_t len2 = 12;
    raw.resize(raw.size() + sizeof(uint32_t));
    std::memcpy(raw.data() + raw.size() - sizeof(uint32_t), &len2, sizeof(uint32_t));
    raw.insert(raw.end(), {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14});

    // Test DATA_PAGE_V1 with both repetition and definition levels
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_repetition_level", int32_t(1)}, // > 0, so repetition levels present
        {"data_page_max_definition_level", int32_t(2)}, // > 0, so definition levels present
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };
    int result = CalculateLevelBytesLength(raw, attribs);
    EXPECT_EQ(28, result); // (4+8) + (4+12) = 12 + 16 = 28
}

TEST(ParquetUtils, CalculateLevelBytesLength_DATA_PAGE_V1_InvalidEncoding) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};

    // Test DATA_PAGE_V1 with non-RLE encoding (should throw exception)
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"data_page_max_definition_level", int32_t(1)},
        {"page_v1_repetition_level_encoding", std::string("BIT_PACKED")},  // Not RLE
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };
    EXPECT_THROW(CalculateLevelBytesLength(raw, attribs), InvalidInputException);
}

TEST(ParquetUtils, CalculateLevelBytesLength_UnknownPageType) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03};

    // Test unknown page type (should throw exception)
    AttributesMap attribs = {
        {"page_type", std::string("UNKNOWN_PAGE_TYPE")}
    };
    EXPECT_THROW(CalculateLevelBytesLength(raw, attribs), InvalidInputException);
}

TEST(ParquetUtils, CalculateLevelBytesLength_InvalidTotalSize) {
    std::vector<uint8_t> raw = {0x01, 0x02};

    // Test DATA_PAGE_V2 with byte lengths exceeding raw data size (should throw exception)
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_definition_level", int32_t(2)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"page_v2_definition_levels_byte_length", int32_t(5)},
        {"page_v2_repetition_levels_byte_length", int32_t(3)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", false}
    };
    EXPECT_THROW(CalculateLevelBytesLength(raw, attribs), InvalidInputException);
}

TEST(ParquetUtils, CalculateLevelBytesLength_NegativeTotalSize) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};

    // Test DATA_PAGE_V2 with negative byte lengths (should throw exception)
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_definition_level", int32_t(2)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"page_v2_definition_levels_byte_length", int32_t(-1)},
        {"page_v2_repetition_levels_byte_length", int32_t(-5)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", false}
    };
    EXPECT_THROW(CalculateLevelBytesLength(raw, attribs), InvalidInputException);
}

// -----------------------------------------------------------------------------
// Tests for CountPresentFromDefinitionLevelsV1 function.
// -----------------------------------------------------------------------------

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_RleAllPresent) {
    auto def_payload = MakeRleDefPayload(10, 1, 1);
    EXPECT_EQ(10u, CountPresentFromDefinitionLevelsV1(def_payload, 10, 1));
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_RleAllNull) {
    auto def_payload = MakeRleDefPayload(10, 0, 1);
    EXPECT_EQ(0u, CountPresentFromDefinitionLevelsV1(def_payload, 10, 1));
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_BitPackedMixed) {
    std::vector<uint32_t> levels = {1, 0, 1, 0, 1, 0, 1, 0};
    auto def_payload = MakeBitPackedDefPayload(levels, 1);
    EXPECT_EQ(4u, CountPresentFromDefinitionLevelsV1(def_payload, 8, 1));
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_MixedRuns) {
    auto rle_part = MakeRleDefPayload(4, 1, 1);  // 4 present
    std::vector<uint32_t> levels = {0, 1, 0, 1, 0, 0, 0, 0};  // +2 present
    auto bp_part = MakeBitPackedDefPayload(levels, 1);
    rle_part.insert(rle_part.end(), bp_part.begin(), bp_part.end());
    EXPECT_EQ(6u, CountPresentFromDefinitionLevelsV1(rle_part, 12, 1));
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_InvalidRunLength) {
    auto def_payload = MakeRleDefPayload(9, 1, 1);  // run_len > num_values
    EXPECT_THROW(CountPresentFromDefinitionLevelsV1(def_payload, 8, 1), InvalidInputException);
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_InvalidLevelExceedsMax) {
    auto def_payload = MakeRleDefPayload(1, 2, 1);  // level 2 > max_def_level 1
    EXPECT_THROW(CountPresentFromDefinitionLevelsV1(def_payload, 1, 1), InvalidInputException);
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_TruncatedVarint) {
    std::vector<uint8_t> def_payload = {0x80};  // continuation bit set, no next byte
    EXPECT_THROW(CountPresentFromDefinitionLevelsV1(def_payload, 1, 1), InvalidInputException);
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_TruncatedRleValue) {
    auto def_payload = EncodeUleb128(2);  // run_len = 1, but missing repeated value byte
    EXPECT_THROW(CountPresentFromDefinitionLevelsV1(def_payload, 1, 1), InvalidInputException);
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_BitPackedCanonical_0to7_88C6FA) {
    // Canonical example from Parquet Encodings.md:
    // values 0..7 with bit_width=3 are packed as bytes 0x88, 0xC6, 0xFA.
    // Bit-packed header for one group of 8 values is varint((1 << 1) | 1) = 0x03.
    std::vector<uint8_t> def_payload = {0x03, 0x88, 0xC6, 0xFA};

    EXPECT_EQ(1u, CountPresentFromDefinitionLevelsV1(def_payload, 8, 7));  // only value 7
    EXPECT_EQ(1u, CountPresentFromDefinitionLevelsV1(def_payload, 8, 3));  // only value 3
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_ManualBytes_RleRunLen4_Level1) {
    // Manual payload:
    // - header 0x08 => RLE run, run_len = 0x08 >> 1 = 4
    // - repeated value byte = 0x01 (bit_width=1, level=1)
    std::vector<uint8_t> def_payload = {0x08, 0x01};
    EXPECT_EQ(4u, CountPresentFromDefinitionLevelsV1(def_payload, 4, 1));
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_ManualBytes_BitPackedAlternating_0xAA) {
    // Manual payload:
    // - header 0x03 => bit-packed, num_groups = 1, run_len = 8
    // - packed byte 0xAA => bits (LSB->MSB): 0,1,0,1,0,1,0,1
    std::vector<uint8_t> def_payload = {0x03, 0xAA};
    EXPECT_EQ(4u, CountPresentFromDefinitionLevelsV1(def_payload, 8, 1));
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_ManualBytes_MixedRleAndBitPacked) {
    // Manual payload:
    // - 0x06,0x01 => RLE run_len=3, level=1
    // - 0x03,0x0F => bit-packed 8 values, bits: 1,1,1,1,0,0,0,0
    // Total values = 3 + 8 = 11; present count at max_def_level=1 is 3 + 4 = 7.
    std::vector<uint8_t> def_payload = {0x06, 0x01, 0x03, 0x0F};
    EXPECT_EQ(7u, CountPresentFromDefinitionLevelsV1(def_payload, 11, 1));
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_BitWidth1_ExhaustiveOneGroup) {
    // Exhaustive check for all 8-value bit-packed patterns at bit_width=1.
    // Payload form: [0x03][packed-byte], where 0x03 means one bit-packed group (8 values).
    for (int packed = 0; packed <= 0xFF; ++packed) {
        std::vector<uint8_t> def_payload = {0x03, static_cast<uint8_t>(packed)};

        size_t ones = 0;
        for (int bit = 0; bit < 8; ++bit) {
            ones += static_cast<size_t>((packed >> bit) & 0x01);
        }

        EXPECT_EQ(ones, CountPresentFromDefinitionLevelsV1(def_payload, 8, 1))
            << "packed=0x" << std::hex << packed;
    }
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_RejectsZeroRleRunLength) {
    // Header 0 means RLE with run_len = 0, which is invalid.
    std::vector<uint8_t> def_payload = {0x00, 0x00};
    EXPECT_THROW(CountPresentFromDefinitionLevelsV1(def_payload, 1, 1), InvalidInputException);
}

TEST(ParquetUtils, CountPresentFromDefinitionLevelsV1_RejectsZeroBitPackedGroups) {
    // Header 1 means bit-packed with num_groups = 0, which is invalid.
    std::vector<uint8_t> def_payload = {0x01};
    EXPECT_THROW(CountPresentFromDefinitionLevelsV1(def_payload, 8, 1), InvalidInputException);
}

// -----------------------------------------------------------------------------
// Tests for DecompressAndSplit function.
// -----------------------------------------------------------------------------

TEST(ParquetUtils, DecompressAndSplit_DataPageV2_Uncompressed) {
    AttributesMap attribs_conv = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(10)},
        {"data_page_max_definition_level", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"page_v2_definition_levels_byte_length", int32_t(5)},
        {"page_v2_repetition_levels_byte_length", int32_t(0)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", false}
    };

    std::vector<uint8_t> level_bytes = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> value_bytes = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0};
    std::vector<uint8_t> plaintext;
    plaintext.insert(plaintext.end(), level_bytes.begin(), level_bytes.end());
    plaintext.insert(plaintext.end(), value_bytes.begin(), value_bytes.end());

    auto result = DecompressAndSplit(
        plaintext, CompressionCodec::UNCOMPRESSED, attribs_conv);

    EXPECT_EQ(level_bytes, result.level_bytes);
    EXPECT_EQ(value_bytes, result.value_bytes);
}

TEST(ParquetUtils, DecompressAndSplit_DataPageV2_Compressed) {
    AttributesMap attribs_conv = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(10)},
        {"data_page_max_definition_level", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"page_v2_definition_levels_byte_length", int32_t(5)},
        {"page_v2_repetition_levels_byte_length", int32_t(0)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", true}
    };

    std::vector<uint8_t> level_bytes = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> value_bytes = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0};
    std::vector<uint8_t> compressed_value_bytes = Compress(value_bytes, CompressionCodec::SNAPPY);

    std::vector<uint8_t> plaintext;
    plaintext.insert(plaintext.end(), level_bytes.begin(), level_bytes.end());
    plaintext.insert(plaintext.end(), compressed_value_bytes.begin(), compressed_value_bytes.end());

    auto result = DecompressAndSplit(
        plaintext, CompressionCodec::SNAPPY, attribs_conv);

    EXPECT_EQ(level_bytes, result.level_bytes);
    EXPECT_EQ(value_bytes, result.value_bytes);
}

TEST(ParquetUtils, DecompressAndSplit_DataPageV2_UnsupportedCompression) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(1)},
        {"data_page_max_definition_level", int32_t(0)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"page_v2_definition_levels_byte_length", int32_t(0)},
        {"page_v2_repetition_levels_byte_length", int32_t(0)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", true}
    };

    std::vector<uint8_t> plaintext = {0x00};
    EXPECT_THROW(
        DecompressAndSplit(plaintext, CompressionCodec::LZO, attribs),
        DBPSUnsupportedException);
}

TEST(ParquetUtils, DecompressAndSplit_DataPageV1_Required_NoLevels) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(4)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"data_page_max_definition_level", int32_t(0)},
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };

    std::vector<uint8_t> value_bytes = {0x11, 0x22, 0x33, 0x44};
    auto result = DecompressAndSplit(value_bytes, CompressionCodec::UNCOMPRESSED, attribs);

    EXPECT_TRUE(result.level_bytes.empty());
    EXPECT_EQ(value_bytes, result.value_bytes);
    EXPECT_EQ(4u, result.num_elements);
}

TEST(ParquetUtils, DecompressAndSplit_DataPageV1_Nullable_RleAllPresent) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(5)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"data_page_max_definition_level", int32_t(1)},
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };

    std::vector<uint8_t> def_payload = MakeRleDefPayload(5, 1, 1);
    std::vector<uint8_t> level_bytes = WrapLengthPrefixed(def_payload);
    std::vector<uint8_t> value_bytes = {0x10, 0x20, 0x30, 0x40, 0x50};
    std::vector<uint8_t> plaintext = Join(level_bytes, value_bytes);

    auto result = DecompressAndSplit(plaintext, CompressionCodec::UNCOMPRESSED, attribs);
    EXPECT_EQ(level_bytes, result.level_bytes);
    EXPECT_EQ(value_bytes, result.value_bytes);
    EXPECT_EQ(5u, result.num_elements);
}

TEST(ParquetUtils, DecompressAndSplit_DataPageV1_Nullable_BitPackedWithRepLevels) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(8)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"data_page_max_definition_level", int32_t(1)},
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };

    // Rep levels are present but ignored for present-count logic.
    std::vector<uint8_t> rep_payload = MakeRleDefPayload(8, 0, 1);
    std::vector<uint8_t> def_payload = MakeBitPackedDefPayload({1, 0, 1, 0, 1, 0, 0, 0}, 1);
    std::vector<uint8_t> level_bytes = WrapLengthPrefixed(rep_payload);
    auto def_wrapped = WrapLengthPrefixed(def_payload);
    level_bytes.insert(level_bytes.end(), def_wrapped.begin(), def_wrapped.end());

    std::vector<uint8_t> value_bytes = {0x01, 0x02, 0x03};
    std::vector<uint8_t> plaintext = Join(level_bytes, value_bytes);

    auto result = DecompressAndSplit(plaintext, CompressionCodec::UNCOMPRESSED, attribs);
    EXPECT_EQ(level_bytes, result.level_bytes);
    EXPECT_EQ(value_bytes, result.value_bytes);
    EXPECT_EQ(3u, result.num_elements);
}

TEST(ParquetUtils, DecompressAndSplit_DataPageV1_InvalidDefinitionPayload) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(4)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"data_page_max_definition_level", int32_t(1)},
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };

    std::vector<uint8_t> def_payload = {0x80};  // truncated varint run header
    std::vector<uint8_t> level_bytes = WrapLengthPrefixed(def_payload);
    std::vector<uint8_t> value_bytes = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<uint8_t> plaintext = Join(level_bytes, value_bytes);

    EXPECT_THROW(
        DecompressAndSplit(plaintext, CompressionCodec::UNCOMPRESSED, attribs),
        InvalidInputException);
}

// -----------------------------------------------------------------------------
// Tests for CompressAndJoin function.
// -----------------------------------------------------------------------------

TEST(ParquetUtils, CompressAndJoin_DataPageV1_Compressed) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(2)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"data_page_max_definition_level", int32_t(1)},
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };

    std::vector<uint8_t> level_bytes;
    append_u32_le(level_bytes, 2); // RLE block length
    level_bytes.insert(level_bytes.end(), {0x04, 0x01});  // RLE run: len=2, level=1
    std::vector<uint8_t> value_bytes = {0x21, 0x22, 0x23, 0x24};

    auto joined = CompressAndJoin(level_bytes, value_bytes, CompressionCodec::SNAPPY, attribs);
    auto expected = Compress(Join(level_bytes, value_bytes), CompressionCodec::SNAPPY);
    EXPECT_EQ(joined, expected);

    auto decomposed = DecompressAndSplit(joined, CompressionCodec::SNAPPY, attribs);
    EXPECT_EQ(decomposed.level_bytes, level_bytes);
    EXPECT_EQ(decomposed.value_bytes, value_bytes);
}

TEST(ParquetUtils, CompressAndJoin_DataPageV2_Uncompressed) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(3)},
        {"data_page_max_definition_level", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"page_v2_definition_levels_byte_length", int32_t(2)},
        {"page_v2_repetition_levels_byte_length", int32_t(1)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", false}
    };

    std::vector<uint8_t> level_bytes = {0x10, 0x11, 0x12}; // 2+1
    std::vector<uint8_t> value_bytes = {0x21, 0x22, 0x23, 0x24};

    auto joined = CompressAndJoin(level_bytes, value_bytes, CompressionCodec::UNCOMPRESSED, attribs);
    std::vector<uint8_t> expected = Join(level_bytes, value_bytes);
    EXPECT_EQ(joined, expected);

    auto decomposed = DecompressAndSplit(joined, CompressionCodec::UNCOMPRESSED, attribs);
    EXPECT_EQ(decomposed.level_bytes, level_bytes);
    EXPECT_EQ(decomposed.value_bytes, value_bytes);
}

TEST(ParquetUtils, CompressAndJoin_DataPageV2_Compressed_RoundTrip) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(4)},
        {"data_page_max_definition_level", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"page_v2_definition_levels_byte_length", int32_t(2)},
        {"page_v2_repetition_levels_byte_length", int32_t(1)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", true}
    };

    std::vector<uint8_t> level_bytes = {0x10, 0x11, 0x12}; // len matches 2+1
    std::vector<uint8_t> value_bytes = {0x21, 0x22, 0x23, 0x24, 0x25};

    auto joined = CompressAndJoin(level_bytes, value_bytes, CompressionCodec::SNAPPY, attribs);
    auto expected_compressed = Compress(value_bytes, CompressionCodec::SNAPPY);
    auto expected_joined = Join(level_bytes, expected_compressed);
    EXPECT_EQ(joined, expected_joined);

    auto decomposed = DecompressAndSplit(joined, CompressionCodec::SNAPPY, attribs);

    EXPECT_EQ(decomposed.level_bytes, level_bytes);
    EXPECT_EQ(decomposed.value_bytes, value_bytes);
}

TEST(ParquetUtils, CompressAndJoin_DataPageV2_LevelLengthMismatch) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(2)},
        {"data_page_max_definition_level", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"page_v2_definition_levels_byte_length", int32_t(2)},
        {"page_v2_repetition_levels_byte_length", int32_t(1)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", true}
    };

    std::vector<uint8_t> level_bytes = {0x10, 0x11}; // expected 3 bytes -> mismatch
    std::vector<uint8_t> value_bytes = {0x21, 0x22, 0x23};

    EXPECT_THROW(
        CompressAndJoin(level_bytes, value_bytes, CompressionCodec::SNAPPY, attribs),
        InvalidInputException);
}

TEST(ParquetUtils, CompressAndJoin_DictionaryPage) {
    AttributesMap attribs = {
        {"page_type", std::string("DICTIONARY_PAGE")}
    };

    std::vector<uint8_t> level_bytes; // must be empty
    std::vector<uint8_t> value_bytes = {0x31, 0x32, 0x33};

    auto joined = CompressAndJoin(level_bytes, value_bytes, CompressionCodec::UNCOMPRESSED, attribs);
    EXPECT_EQ(joined, value_bytes);
}

TEST(ParquetUtils, CompressAndJoin_UnsupportedCompression) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"data_page_max_definition_level", int32_t(0)},
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };

    std::vector<uint8_t> level_bytes;
    std::vector<uint8_t> value_bytes = {0x40};

    EXPECT_THROW(
        CompressAndJoin(level_bytes, value_bytes, CompressionCodec::LZO, attribs),
        DBPSUnsupportedException);
}

TEST(ParquetUtils, CompressAndJoin_UnsupportedEncoding) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(1)}, // triggers repetition level parsing
        {"data_page_max_definition_level", int32_t(0)},
        {"page_v1_repetition_level_encoding", std::string("BIT_PACKED")}, // unsupported
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };

    // Build minimal level bytes that would be valid if encoding were RLE: len + payload
    std::vector<uint8_t> level_bytes;
    append_u32_le(level_bytes, 1);
    level_bytes.push_back(0x00);

    std::vector<uint8_t> value_bytes = {0x01, 0x02};

    EXPECT_THROW(
        CompressAndJoin(level_bytes, value_bytes, CompressionCodec::UNCOMPRESSED, attribs),
        InvalidInputException);
}

// =============================================================================
// ReinterpretValueBytesAsTypedValuesBuffer tests
// =============================================================================

TEST(ParquetUtils, Reinterpret_INT32) {
    std::vector<int32_t> values = {-1, 0, 2147483647};
    std::vector<uint8_t> bytes(reinterpret_cast<const uint8_t*>(values.data()),
                               reinterpret_cast<const uint8_t*>(values.data()) + values.size() * sizeof(int32_t));

    TypedValuesBuffer result = ReinterpretValueBytesAsTypedValuesBuffer(
        bytes, values.size(), Type::INT32, std::nullopt, Encoding::PLAIN);

    auto* buf = std::get_if<TypedBufferI32>(&result);
    ASSERT_NE(nullptr, buf);

    size_t i = 0;
    for (auto val : *buf) {
        EXPECT_EQ(values[i], val);
        ++i;
    }
    EXPECT_EQ(values.size(), i);
}

TEST(ParquetUtils, Reinterpret_DOUBLE) {
    std::vector<double> values = {0.0, 1.5, -3.75, 1.7976931348623157e+308};
    std::vector<uint8_t> bytes(reinterpret_cast<const uint8_t*>(values.data()),
                               reinterpret_cast<const uint8_t*>(values.data()) + values.size() * sizeof(double));

    TypedValuesBuffer result = ReinterpretValueBytesAsTypedValuesBuffer(
        bytes, values.size(), Type::DOUBLE, std::nullopt, Encoding::PLAIN);

    auto* buf = std::get_if<TypedBufferDouble>(&result);
    ASSERT_NE(nullptr, buf);

    size_t i = 0;
    for (auto val : *buf) {
        EXPECT_DOUBLE_EQ(values[i], val);
        ++i;
    }
    EXPECT_EQ(values.size(), i);
}

TEST(ParquetUtils, Reinterpret_INT96) {
    std::vector<Int96> expected = {
        {0, 0, 0},
        {-1, 2147483647, -2147483648},
        {305419896, 0, 1},
        {1, 1, 1},
        {123456789, -987654321, 42}
    };
    std::vector<uint8_t> bytes;
    for (const auto& v : expected) {
        bytes.insert(bytes.end(), reinterpret_cast<const uint8_t*>(&v),
                     reinterpret_cast<const uint8_t*>(&v) + sizeof(Int96));
    }

    TypedValuesBuffer result = ReinterpretValueBytesAsTypedValuesBuffer(
        bytes, expected.size(), Type::INT96, std::nullopt, Encoding::PLAIN);

    auto* buf = std::get_if<TypedBufferInt96>(&result);
    ASSERT_NE(nullptr, buf);
    size_t i = 0;
    for (auto val : *buf) {
        EXPECT_EQ(expected[i].lo, val.lo);
        EXPECT_EQ(expected[i].mid, val.mid);
        EXPECT_EQ(expected[i].hi, val.hi);
        ++i;
    }
    EXPECT_EQ(expected.size(), i);
}

TEST(ParquetUtils, Reinterpret_BYTE_ARRAY) {
    std::vector<std::vector<uint8_t>> expected = {
        {},
        {0x42},
        {0x00, 0xFF, 0x80},
        {'h', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd'},
        {}
    };

    std::vector<uint8_t> bytes;
    for (const auto& elem : expected) {
        uint32_t len = static_cast<uint32_t>(elem.size());
        bytes.insert(bytes.end(), reinterpret_cast<const uint8_t*>(&len),
                     reinterpret_cast<const uint8_t*>(&len) + sizeof(len));
        bytes.insert(bytes.end(), elem.begin(), elem.end());
    }

    TypedValuesBuffer result = ReinterpretValueBytesAsTypedValuesBuffer(
        bytes, expected.size(), Type::BYTE_ARRAY, std::nullopt, Encoding::PLAIN);

    auto* buf = std::get_if<TypedBufferRawBytesVariableSized>(&result);
    ASSERT_NE(nullptr, buf);

    size_t i = 0;
    for (auto val : *buf) {
        EXPECT_EQ(expected[i], std::vector<uint8_t>(val.begin(), val.end()));
        ++i;
    }
    EXPECT_EQ(expected.size(), i);
}

TEST(ParquetUtils, Reinterpret_FIXED_LEN_BYTE_ARRAY) {
    std::vector<std::vector<uint8_t>> expected = {
        {0x00, 0x00, 0x00, 0x00, 0x00},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        {0x01, 0x02, 0x03, 0x04, 0x05},
        {0xDE, 0xAD, 0xBE, 0xEF, 0x42}
    };
    const int element_len = 5;

    std::vector<uint8_t> bytes;
    for (const auto& elem : expected) {
        bytes.insert(bytes.end(), elem.begin(), elem.end());
    }

    TypedValuesBuffer result = ReinterpretValueBytesAsTypedValuesBuffer(
        bytes, expected.size(), Type::FIXED_LEN_BYTE_ARRAY, element_len, Encoding::PLAIN);

    auto* buf = std::get_if<TypedBufferRawBytesFixedSized>(&result);
    ASSERT_NE(nullptr, buf);

    size_t i = 0;
    for (auto val : *buf) {
        EXPECT_EQ(expected[i], std::vector<uint8_t>(val.begin(), val.end()));
        ++i;
    }
    EXPECT_EQ(expected.size(), i);
}

TEST(ParquetUtils, Reinterpret_UnsupportedEncoding) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04};
    EXPECT_THROW(
        ReinterpretValueBytesAsTypedValuesBuffer(bytes, 1u, Type::INT32, std::nullopt, Encoding::RLE),
        DBPSUnsupportedException);
}

TEST(ParquetUtils, Reinterpret_RLE_DICTIONARY_Throws) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04};
    EXPECT_THROW(
        ReinterpretValueBytesAsTypedValuesBuffer(bytes, 1u, Type::INT32, std::nullopt, Encoding::RLE_DICTIONARY),
        DBPSUnsupportedException);
}

TEST(ParquetUtils, Reinterpret_BOOLEAN_Throws) {
    std::vector<uint8_t> bytes = {0xB4};
    EXPECT_THROW(
        ReinterpretValueBytesAsTypedValuesBuffer(bytes, 1u, Type::BOOLEAN, std::nullopt, Encoding::PLAIN),
        DBPSUnsupportedException);
}

TEST(ParquetUtils, Reinterpret_InvalidDataSize) {
    std::vector<uint8_t> bytes = {0xAA, 0xBB, 0xCC};
    auto result = ReinterpretValueBytesAsTypedValuesBuffer(
        bytes, 1u, Type::INT32, std::nullopt, Encoding::PLAIN);

    auto* buf = std::get_if<TypedBufferI32>(&result);
    ASSERT_NE(nullptr, buf);
    EXPECT_THROW(
        { for (auto val : *buf) { (void)val; } },
        InvalidInputException);
}

TEST(ParquetUtils, Reinterpret_FIXED_LEN_BYTE_ARRAY_MissingLength_Throws) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
    EXPECT_THROW(
        ReinterpretValueBytesAsTypedValuesBuffer(
            bytes, 1u, Type::FIXED_LEN_BYTE_ARRAY, std::nullopt, Encoding::PLAIN),
        InvalidInputException);
}

TEST(ParquetUtils, Reinterpret_FIXED_LEN_BYTE_ARRAY_ZeroLength_Throws) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
    EXPECT_THROW(
        ReinterpretValueBytesAsTypedValuesBuffer(bytes, 1u, Type::FIXED_LEN_BYTE_ARRAY, 0, Encoding::PLAIN),
        InvalidInputException);
}

TEST(ParquetUtils, Reinterpret_FIXED_LEN_BYTE_ARRAY_NegativeLength_Throws) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
    EXPECT_THROW(
        ReinterpretValueBytesAsTypedValuesBuffer(bytes, 1u, Type::FIXED_LEN_BYTE_ARRAY, -1, Encoding::PLAIN),
        InvalidInputException);
}

TEST(ParquetUtils, Reinterpret_EmptyBytes_FixedSize) {
    std::vector<uint8_t> bytes;
    TypedValuesBuffer result = ReinterpretValueBytesAsTypedValuesBuffer(
        bytes, 0u, Type::DOUBLE, std::nullopt, Encoding::PLAIN);

    auto* buf = std::get_if<TypedBufferDouble>(&result);
    ASSERT_NE(nullptr, buf);
    size_t count = 0;
    for (auto val : *buf) { (void)val; ++count; }
    EXPECT_EQ(0u, count);
}

TEST(ParquetUtils, Reinterpret_EmptyBytes_VariableSize) {
    std::vector<uint8_t> bytes;
    TypedValuesBuffer result = ReinterpretValueBytesAsTypedValuesBuffer(
        bytes, 0u, Type::BYTE_ARRAY, std::nullopt, Encoding::PLAIN);

    auto* buf = std::get_if<TypedBufferRawBytesVariableSized>(&result);
    ASSERT_NE(nullptr, buf);
    size_t count = 0;
    for (auto val : *buf) { (void)val; ++count; }
    EXPECT_EQ(0u, count);
}

// =============================================================================
// Round-trip tests: Reinterpret -> iterate -> write -> GetAsValueBytes -> compare
// =============================================================================

TEST(ParquetUtils, RoundTrip_INT32) {
    std::vector<int32_t> values = {-2147483648, 0, 42, 2147483647};
    std::vector<uint8_t> input_bytes(
        reinterpret_cast<const uint8_t*>(values.data()),
        reinterpret_cast<const uint8_t*>(values.data()) + values.size() * sizeof(int32_t));

    auto read_buf = ReinterpretValueBytesAsTypedValuesBuffer(
        input_bytes, values.size(), Type::INT32, std::nullopt, Encoding::PLAIN);

    auto* src = std::get_if<TypedBufferI32>(&read_buf);
    ASSERT_NE(nullptr, src);

    TypedBufferI32 write_buf{values.size()};
    size_t pos = 0;
    for (auto val : *src) {
        write_buf.SetElement(pos++, val);
    }

    TypedValuesBuffer variant_buf = std::move(write_buf);
    std::vector<uint8_t> output_bytes = GetTypedValuesBufferAsValueBytes(std::move(variant_buf));
    EXPECT_EQ(input_bytes, output_bytes);
}

TEST(ParquetUtils, RoundTrip_BYTE_ARRAY) {
    std::vector<std::vector<uint8_t>> payloads = {
        {0xCA, 0xFE},
        {},
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
        {0xFF}
    };

    std::vector<uint8_t> input_bytes;
    for (const auto& p : payloads) {
        uint32_t len = static_cast<uint32_t>(p.size());
        input_bytes.insert(input_bytes.end(),
            reinterpret_cast<const uint8_t*>(&len),
            reinterpret_cast<const uint8_t*>(&len) + sizeof(len));
        input_bytes.insert(input_bytes.end(), p.begin(), p.end());
    }

    auto read_buf = ReinterpretValueBytesAsTypedValuesBuffer(
        input_bytes, payloads.size(), Type::BYTE_ARRAY, std::nullopt, Encoding::PLAIN);

    auto* src = std::get_if<TypedBufferRawBytesVariableSized>(&read_buf);
    ASSERT_NE(nullptr, src);

    TypedBufferRawBytesVariableSized write_buf{payloads.size(), input_bytes.size(), true};
    size_t pos = 0;
    for (auto val : *src) {
        write_buf.SetElement(pos++, val);
    }
    EXPECT_EQ(payloads.size(), pos);

    TypedValuesBuffer variant_buf = std::move(write_buf);
    std::vector<uint8_t> output_bytes = GetTypedValuesBufferAsValueBytes(std::move(variant_buf));
    EXPECT_EQ(input_bytes, output_bytes);
}

TEST(ParquetUtils, RoundTrip_FIXED_LEN_BYTE_ARRAY) {
    const int element_len = 7;
    std::vector<std::vector<uint8_t>> payloads = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9},
        {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70}
    };

    std::vector<uint8_t> input_bytes;
    for (const auto& p : payloads) {
        input_bytes.insert(input_bytes.end(), p.begin(), p.end());
    }

    auto read_buf = ReinterpretValueBytesAsTypedValuesBuffer(
        input_bytes, payloads.size(), Type::FIXED_LEN_BYTE_ARRAY, element_len, Encoding::PLAIN);

    auto* src = std::get_if<TypedBufferRawBytesFixedSized>(&read_buf);
    ASSERT_NE(nullptr, src);

    TypedBufferRawBytesFixedSized write_buf{
        payloads.size(), 0, RawBytesFixedSizedCodec{static_cast<size_t>(element_len)}};
    size_t pos = 0;
    for (auto val : *src) {
        write_buf.SetElement(pos++, val);
    }
    EXPECT_EQ(payloads.size(), pos);

    TypedValuesBuffer variant_buf = std::move(write_buf);
    std::vector<uint8_t> output_bytes = GetTypedValuesBufferAsValueBytes(std::move(variant_buf));
    EXPECT_EQ(input_bytes, output_bytes);
}

// =============================================================================
// GetTypedValuesBufferAsValueBytes standalone tests
// =============================================================================

TEST(ParquetUtils, GetAsValueBytes_WrittenBuffer) {
    std::vector<double> values = {-0.0, 1.0e-300, 3.141592653589793, -1.7976931348623157e+308, 1.0};

    TypedBufferDouble write_buf{values.size()};
    for (size_t i = 0; i < values.size(); ++i) {
        write_buf.SetElement(i, values[i]);
    }

    std::vector<uint8_t> expected(
        reinterpret_cast<const uint8_t*>(values.data()),
        reinterpret_cast<const uint8_t*>(values.data()) + values.size() * sizeof(double));

    TypedValuesBuffer variant_buf = std::move(write_buf);
    std::vector<uint8_t> output_bytes = GetTypedValuesBufferAsValueBytes(std::move(variant_buf));
    EXPECT_EQ(expected, output_bytes);
}
