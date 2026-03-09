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

#include "encryptor_utils.h"
#include "../../common/exceptions.h"
#include <gtest/gtest.h>

using namespace dbps::processing;

// --- WriteHeader + ReadHeader round-trip ---

TEST(EncryptorUtils, FixedHeader_RoundTrip) {
    std::vector<uint8_t> buf(kFixedHeaderLength, 0);
    EncryptedValueHeader written{true, 42, 8};
    WriteHeader(buf, written);

    auto read = ReadHeader(tcb::span<const uint8_t>(buf));
    EXPECT_TRUE(read.is_fixed);
    EXPECT_EQ(read.num_elements, 42u);
    EXPECT_EQ(read.element_size, 8u);
}

TEST(EncryptorUtils, VariableHeader_RoundTrip) {
    std::vector<uint8_t> buf(kVariableHeaderLength, 0);
    EncryptedValueHeader written{false, 100, 0};
    WriteHeader(buf, written);

    auto read = ReadHeader(tcb::span<const uint8_t>(buf));
    EXPECT_FALSE(read.is_fixed);
    EXPECT_EQ(read.num_elements, 100u);
    EXPECT_EQ(read.element_size, 0u);
}

TEST(EncryptorUtils, FixedHeader_ZeroElements) {
    std::vector<uint8_t> buf(kFixedHeaderLength, 0);
    WriteHeader(buf, {true, 0, 0});

    auto read = ReadHeader(tcb::span<const uint8_t>(buf));
    EXPECT_TRUE(read.is_fixed);
    EXPECT_EQ(read.num_elements, 0u);
    EXPECT_EQ(read.element_size, 0u);
}

TEST(EncryptorUtils, WriteHeader_Fixed_WritesExpectedWireFormat) {
    std::vector<uint8_t> buf(kFixedHeaderLength, 0xEE);
    WriteHeader(buf, {true, 42u, 8u});

    // [tag=0x01][count=42 little-endian][elem_size=8 little-endian]
    const std::vector<uint8_t> expected = {
        0x01,
        0x2A, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00
    };
    EXPECT_EQ(buf, expected);
}

TEST(EncryptorUtils, WriteHeader_Variable_WritesExpectedWireFormat) {
    std::vector<uint8_t> buf(kVariableHeaderLength, 0xEE);
    WriteHeader(buf, {false, 100u, 0u});

    // [tag=0x00][count=100 little-endian]
    const std::vector<uint8_t> expected = {
        0x00,
        0x64, 0x00, 0x00, 0x00
    };
    EXPECT_EQ(buf, expected);
}

// --- Error cases ---

TEST(EncryptorUtils, WriteHeader_BufferTooSmall_Fixed) {
    std::vector<uint8_t> buf(kFixedHeaderLength - 1, 0);
    EXPECT_THROW(WriteHeader(buf, {true, 1, 4}), InvalidInputException);
}

TEST(EncryptorUtils, WriteHeader_BufferTooSmall_Variable) {
    std::vector<uint8_t> buf(kVariableHeaderLength - 1, 0);
    EXPECT_THROW(WriteHeader(buf, {false, 1, 0}), InvalidInputException);
}

TEST(EncryptorUtils, ReadHeader_EmptyInput) {
    std::vector<uint8_t> empty;
    EXPECT_THROW(ReadHeader(tcb::span<const uint8_t>(empty)), InvalidInputException);
}

TEST(EncryptorUtils, ReadHeader_TruncatedFixed) {
    std::vector<uint8_t> buf = {kFixedSizeTag, 0, 0};
    EXPECT_THROW(ReadHeader(tcb::span<const uint8_t>(buf)), InvalidInputException);
}

TEST(EncryptorUtils, ReadHeader_TruncatedVariable) {
    std::vector<uint8_t> buf = {kVariableSizeTag, 0};
    EXPECT_THROW(ReadHeader(tcb::span<const uint8_t>(buf)), InvalidInputException);
}
