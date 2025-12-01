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

#include "compression_utils.h"
#include "exceptions.h"
#include <vector>
#include <cstdint>
#include <gtest/gtest.h>

using namespace dbps::external;
using namespace dbps::compression;

TEST(CompressionUtils, Compress_Uncompressed) {
    std::vector<uint8_t> input = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> result = Compress(input, CompressionCodec::UNCOMPRESSED);
    EXPECT_EQ(input, result);
}

TEST(CompressionUtils, Decompress_Uncompressed) {
    std::vector<uint8_t> input = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> result = Decompress(input, CompressionCodec::UNCOMPRESSED);
    EXPECT_EQ(input, result);
}

TEST(CompressionUtils, Compress_Empty) {
    std::vector<uint8_t> input;
    std::vector<uint8_t> result = Compress(input, CompressionCodec::SNAPPY);
    EXPECT_EQ(input, result);
}

TEST(CompressionUtils, Decompress_Empty) {
    std::vector<uint8_t> input;
    std::vector<uint8_t> result = Decompress(input, CompressionCodec::SNAPPY);
    EXPECT_EQ(input, result);
}

TEST(CompressionUtils, CompressDecompress_Snappy_RoundTrip) {
    std::vector<uint8_t> original = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::vector<uint8_t> compressed = Compress(original, CompressionCodec::SNAPPY);
    std::vector<uint8_t> decompressed = Decompress(compressed, CompressionCodec::SNAPPY);
    EXPECT_EQ(original, decompressed);
    // Verify that compression actually occurred (compressed data should differ from original)
    EXPECT_NE(original, compressed);
}

TEST(CompressionUtils, Decompress_InvalidData) {
    std::vector<uint8_t> invalid_data = {0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT_THROW(Decompress(invalid_data, CompressionCodec::SNAPPY), InvalidInputException);
}

TEST(CompressionUtils, Compress_UnsupportedCodec) {
    std::vector<uint8_t> input = {0x01, 0x02, 0x03};
    EXPECT_THROW(Compress(input, CompressionCodec::GZIP), DBPSUnsupportedException);
}

TEST(CompressionUtils, Decompress_UnsupportedCodec) {
    std::vector<uint8_t> input = {0x01, 0x02, 0x03};
    EXPECT_THROW(Decompress(input, CompressionCodec::GZIP), DBPSUnsupportedException);
}

TEST(CompressionUtils, CompressDecompress_Snappy_SingleByte) {
    std::vector<uint8_t> original = {0x42};
    std::vector<uint8_t> compressed = Compress(original, CompressionCodec::SNAPPY);
    std::vector<uint8_t> decompressed = Decompress(compressed, CompressionCodec::SNAPPY);
    EXPECT_EQ(original, decompressed);
    // Verify that compression actually occurred (compressed data should differ from original)
    EXPECT_NE(original, compressed);
}

TEST(CompressionUtils, CompressDecompress_Snappy_LargeData) {
    std::vector<uint8_t> original;
    original.resize(10000);
    for (size_t i = 0; i < original.size(); ++i) {
        original[i] = static_cast<uint8_t>(i % 256);
    }
    std::vector<uint8_t> compressed = Compress(original, CompressionCodec::SNAPPY);
    std::vector<uint8_t> decompressed = Decompress(compressed, CompressionCodec::SNAPPY);
    EXPECT_EQ(original, decompressed);
    // Verify that compression actually occurred (compressed data should differ from original)
    EXPECT_NE(original, compressed);
}

TEST(CompressionUtils, CompressDecompress_Snappy_RepeatingPattern) {
    std::vector<uint8_t> original;
    original.resize(1000, 0xAA);
    std::vector<uint8_t> compressed = Compress(original, CompressionCodec::SNAPPY);
    std::vector<uint8_t> decompressed = Decompress(compressed, CompressionCodec::SNAPPY);
    EXPECT_EQ(original, decompressed);
    EXPECT_LT(compressed.size(), original.size());
}

TEST(CompressionUtils, CompressDecompress_Snappy_TextData) {
    std::string text = "The quick brown fox jumps over the lazy dog. This is a test string.";
    std::vector<uint8_t> original(text.begin(), text.end());
    std::vector<uint8_t> compressed = Compress(original, CompressionCodec::SNAPPY);
    std::vector<uint8_t> decompressed = Decompress(compressed, CompressionCodec::SNAPPY);
    EXPECT_EQ(original, decompressed);
}

TEST(CompressionUtils, CompressDecompress_Snappy_BinaryData) {
    std::vector<uint8_t> original = {0x00, 0xFF, 0xAA, 0x55, 0x11, 0xEE, 0x99, 0x66};
    std::vector<uint8_t> compressed = Compress(original, CompressionCodec::SNAPPY);
    std::vector<uint8_t> decompressed = Decompress(compressed, CompressionCodec::SNAPPY);
    EXPECT_EQ(original, decompressed);
}

TEST(CompressionUtils, CompressDecompress_Snappy_MultipleRoundTrips) {
    std::vector<uint8_t> original = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::vector<uint8_t> data = original;
    for (int i = 0; i < 5; ++i) {
        data = Compress(data, CompressionCodec::SNAPPY);
        data = Decompress(data, CompressionCodec::SNAPPY);
    }
    EXPECT_EQ(original, data);
}

TEST(CompressionUtils, Compress_Snappy_CompressionRatio) {
    std::vector<uint8_t> original;
    original.resize(5000, 0x42);
    std::vector<uint8_t> compressed = Compress(original, CompressionCodec::SNAPPY);
    EXPECT_LE(compressed.size(), original.size());
    EXPECT_GT(compressed.size(), 0);
}

TEST(CompressionUtils, Decompress_InvalidData_Empty) {
    std::vector<uint8_t> empty_data = {};
    std::vector<uint8_t> result = Decompress(empty_data, CompressionCodec::SNAPPY);
    EXPECT_EQ(empty_data, result);
}

TEST(CompressionUtils, Decompress_InvalidData_TooShort) {
    std::vector<uint8_t> invalid_data = {0x01};
    EXPECT_THROW(Decompress(invalid_data, CompressionCodec::SNAPPY), InvalidInputException);
}

TEST(CompressionUtils, Compress_UnsupportedCodec_AllTypes) {
    std::vector<uint8_t> input = {0x01, 0x02, 0x03};
    EXPECT_THROW(Compress(input, CompressionCodec::BROTLI), DBPSUnsupportedException);
    EXPECT_THROW(Compress(input, CompressionCodec::ZSTD), DBPSUnsupportedException);
    EXPECT_THROW(Compress(input, CompressionCodec::LZ4), DBPSUnsupportedException);
}

TEST(CompressionUtils, Decompress_UnsupportedCodec_AllTypes) {
    std::vector<uint8_t> input = {0x01, 0x02, 0x03};
    EXPECT_THROW(Decompress(input, CompressionCodec::BROTLI), DBPSUnsupportedException);
    EXPECT_THROW(Decompress(input, CompressionCodec::ZSTD), DBPSUnsupportedException);
    EXPECT_THROW(Decompress(input, CompressionCodec::LZ4), DBPSUnsupportedException);
}

