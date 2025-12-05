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

#include "bytes_utils.h"
#include "exceptions.h"
#include <vector>
#include <gtest/gtest.h>

TEST(BytesUtils, Split_Normal) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    SplitBytesPair result = Split(bytes, 3);
    
    EXPECT_EQ(3, result.leading.size());
    EXPECT_EQ(3, result.trailing.size());
    EXPECT_EQ(std::vector<uint8_t>({0x01, 0x02, 0x03}), result.leading);
    EXPECT_EQ(std::vector<uint8_t>({0x04, 0x05, 0x06}), result.trailing);
}

TEST(BytesUtils, Split_AtBeginning) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
    SplitBytesPair result = Split(bytes, 0);
    
    EXPECT_EQ(0, result.leading.size());
    EXPECT_EQ(3, result.trailing.size());
    EXPECT_EQ(bytes, result.trailing);
}

TEST(BytesUtils, Split_AtEnd) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
    SplitBytesPair result = Split(bytes, 3);
    
    EXPECT_EQ(3, result.leading.size());
    EXPECT_EQ(0, result.trailing.size());
    EXPECT_EQ(bytes, result.leading);
}

TEST(BytesUtils, Split_InvalidIndex_Negative) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
    EXPECT_THROW(Split(bytes, -1), InvalidInputException);
}

TEST(BytesUtils, Split_InvalidIndex_TooLarge) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
    EXPECT_THROW(Split(bytes, 4), InvalidInputException);
}

TEST(BytesUtils, Join_Normal) {
    std::vector<uint8_t> leading = {0x01, 0x02, 0x03};
    std::vector<uint8_t> trailing = {0x04, 0x05, 0x06};
    std::vector<uint8_t> result = Join(leading, trailing);
    
    EXPECT_EQ(6, result.size());
    EXPECT_EQ(std::vector<uint8_t>({0x01, 0x02, 0x03, 0x04, 0x05, 0x06}), result);
}

TEST(BytesUtils, Join_EmptyLeading) {
    std::vector<uint8_t> leading;
    std::vector<uint8_t> trailing = {0x04, 0x05, 0x06};
    std::vector<uint8_t> result = Join(leading, trailing);
    
    EXPECT_EQ(3, result.size());
    EXPECT_EQ(trailing, result);
}

TEST(BytesUtils, Join_EmptyTrailing) {
    std::vector<uint8_t> leading = {0x01, 0x02, 0x03};
    std::vector<uint8_t> trailing;
    std::vector<uint8_t> result = Join(leading, trailing);
    
    EXPECT_EQ(3, result.size());
    EXPECT_EQ(leading, result);
}

TEST(BytesUtils, Join_BothEmpty) {
    std::vector<uint8_t> leading;
    std::vector<uint8_t> trailing;
    std::vector<uint8_t> result = Join(leading, trailing);
    
    EXPECT_TRUE(result.empty());
}

TEST(BytesUtils, SplitAndJoin_RoundTrip) {
    std::vector<uint8_t> original = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    SplitBytesPair split_result = Split(original, 3);
    std::vector<uint8_t> joined = Join(split_result.leading, split_result.trailing);
    
    EXPECT_EQ(original, joined);
}

TEST(BytesUtils, JoinWithLengthPrefix_Normal) {
    std::vector<uint8_t> leading = {0x01, 0x02, 0x03};
    std::vector<uint8_t> trailing = {0x04, 0x05, 0x06};
    std::vector<uint8_t> result = JoinWithLengthPrefix(leading, trailing);
    
    // Expected: [0x03, 0x00, 0x00, 0x00] (length=3 in little-endian) + leading + trailing
    EXPECT_EQ(10, result.size()); // 4 bytes length + 3 bytes leading + 3 bytes trailing
    EXPECT_EQ(0x03, result[0]);
    EXPECT_EQ(0x00, result[1]);
    EXPECT_EQ(0x00, result[2]);
    EXPECT_EQ(0x00, result[3]);
    EXPECT_EQ(0x01, result[4]);
    EXPECT_EQ(0x02, result[5]);
    EXPECT_EQ(0x03, result[6]);
    EXPECT_EQ(0x04, result[7]);
    EXPECT_EQ(0x05, result[8]);
    EXPECT_EQ(0x06, result[9]);
}

TEST(BytesUtils, JoinWithLengthPrefix_EmptyLeading) {
    std::vector<uint8_t> leading;
    std::vector<uint8_t> trailing = {0x04, 0x05, 0x06};
    std::vector<uint8_t> result = JoinWithLengthPrefix(leading, trailing);
    
    EXPECT_EQ(7, result.size()); // 4 bytes length + 0 bytes leading + 3 bytes trailing
    EXPECT_EQ(0x00, result[0]); // length = 0
    EXPECT_EQ(0x00, result[1]);
    EXPECT_EQ(0x00, result[2]);
    EXPECT_EQ(0x00, result[3]);
    EXPECT_EQ(0x04, result[4]);
    EXPECT_EQ(0x05, result[5]);
    EXPECT_EQ(0x06, result[6]);
}

TEST(BytesUtils, JoinWithLengthPrefix_EmptyTrailing) {
    std::vector<uint8_t> leading = {0x01, 0x02, 0x03};
    std::vector<uint8_t> trailing;
    std::vector<uint8_t> result = JoinWithLengthPrefix(leading, trailing);
    
    EXPECT_EQ(7, result.size()); // 4 bytes length + 3 bytes leading + 0 bytes trailing
    EXPECT_EQ(0x03, result[0]); // length = 3
    EXPECT_EQ(0x01, result[4]);
    EXPECT_EQ(0x02, result[5]);
    EXPECT_EQ(0x03, result[6]);
}

TEST(BytesUtils, SplitWithLengthPrefix_Normal) {
    // Create data with JoinWithLengthPrefix
    std::vector<uint8_t> leading = {0x01, 0x02, 0x03};
    std::vector<uint8_t> trailing = {0x04, 0x05, 0x06};
    std::vector<uint8_t> joined = JoinWithLengthPrefix(leading, trailing);
    
    // Parse it back
    SplitBytesPair result = SplitWithLengthPrefix(joined);
    
    EXPECT_EQ(leading, result.leading);
    EXPECT_EQ(trailing, result.trailing);
}

TEST(BytesUtils, SplitWithLengthPrefix_InvalidTooShort) {
    std::vector<uint8_t> invalid = {0x01, 0x02}; // Less than 4 bytes
    EXPECT_THROW(SplitWithLengthPrefix(invalid), InvalidInputException);
}

TEST(BytesUtils, SplitWithLengthPrefix_InvalidInsufficientData) {
    // Length prefix says 10 bytes, but we only have 4 bytes total
    std::vector<uint8_t> invalid = {0x0A, 0x00, 0x00, 0x00}; // length = 10, but only 4 bytes total
    EXPECT_THROW(SplitWithLengthPrefix(invalid), InvalidInputException);
}

TEST(BytesUtils, JoinWithLengthPrefixAndSplit_RoundTrip) {
    std::vector<uint8_t> leading = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> trailing = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    
    std::vector<uint8_t> joined = JoinWithLengthPrefix(leading, trailing);
    SplitBytesPair parsed = SplitWithLengthPrefix(joined);
    
    EXPECT_EQ(leading, parsed.leading);
    EXPECT_EQ(trailing, parsed.trailing);
}

