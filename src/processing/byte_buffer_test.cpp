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

#include "byte_buffer.h"

#include <gtest/gtest.h>
#include <vector>
#include <cstdint>

#include "exceptions.h"

using dbps::processing::ByteBuffer;

class ByteBufferTestProxy : public ByteBuffer {
public:
    ByteBufferTestProxy(
        tcb::span<const uint8_t> elements_span)
        : ByteBuffer(elements_span) {}
    ByteBufferTestProxy(
        tcb::span<const uint8_t> elements_span,
        size_t element_size)
        : ByteBuffer(elements_span, element_size) {}
    ByteBufferTestProxy(size_t num_elements)
        : ByteBuffer(num_elements, 0, false) {}
    ByteBufferTestProxy(
        size_t num_elements,
        size_t reserved_bytes_hint,
        bool use_reserve_hint)
        : ByteBuffer(num_elements, reserved_bytes_hint, use_reserve_hint) {}
    ByteBufferTestProxy(size_t num_elements, size_t element_size)
        : ByteBuffer(num_elements, element_size) {}

    size_t GetNumElements() const { return num_elements_; }
    bool GetHasFixedSizedElements() const { return has_fixed_sized_elements_; }
    size_t GetElementSize() const { return element_size_; }
    const std::vector<size_t>& GetOffsets() const { return offsets_; }
};

namespace {

void ExpectCommonState(
    const ByteBufferTestProxy& buffer,
    size_t expected_num_elements,
    bool expected_fixed_size_flag,
    size_t expected_element_size) {
    EXPECT_EQ(buffer.GetNumElements(), expected_num_elements);
    EXPECT_EQ(buffer.GetHasFixedSizedElements(), expected_fixed_size_flag);
    EXPECT_EQ(buffer.GetElementSize(), expected_element_size);
}

} // namespace

TEST(ByteBufferTest, ConstructFixedSize_ValidBuffer_InitializesExpectedState) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes), 2);
    ExpectCommonState(buffer, 3u, true, 2u);
    EXPECT_TRUE(buffer.GetOffsets().empty());
}

TEST(ByteBufferTest, GetElement_FixedSize_ReturnsExpectedSlices) {
    std::vector<uint8_t> bytes = {0x10, 0x11, 0x20, 0x21, 0x30, 0x31};
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes), 2);

    const auto first = buffer.getElement(0);
    const auto second = buffer.getElement(1);
    const auto third = buffer.getElement(2);

    ASSERT_EQ(first.size(), 2u);
    ASSERT_EQ(second.size(), 2u);
    ASSERT_EQ(third.size(), 2u);
    EXPECT_EQ(first[0], 0x10);
    EXPECT_EQ(first[1], 0x11);
    EXPECT_EQ(second[0], 0x20);
    EXPECT_EQ(second[1], 0x21);
    EXPECT_EQ(third[0], 0x30);
    EXPECT_EQ(third[1], 0x31);
}

TEST(ByteBufferTest, ConstructFixedSize_ZeroElementSize_Throws) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04};
    EXPECT_THROW((void)ByteBufferTestProxy(tcb::span<const uint8_t>(bytes), 0), InvalidInputException);
}

TEST(ByteBufferTest, ConstructFixedSize_NonDivisibleSize_Throws) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
    EXPECT_THROW((void)ByteBufferTestProxy(tcb::span<const uint8_t>(bytes), 2), InvalidInputException);
}

TEST(ByteBufferTest, ConstructVariableSize_ValidEncodedBuffer_InitializesExpectedState) {
    // [len=5]["ABCDE"][len=7]["1234567"]
    std::vector<uint8_t> bytes = {
        0x05, 0x00, 0x00, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x07, 0x00, 0x00, 0x00, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes));
    ExpectCommonState(buffer, 2u, false, 0u);
    ASSERT_EQ(buffer.GetOffsets().size(), 2u);
    EXPECT_EQ(buffer.GetOffsets()[0], 0u);
    EXPECT_EQ(buffer.GetOffsets()[1], 9u);
}

TEST(ByteBufferTest, GetElement_VariableSize_ReturnsExpectedPayload) {
    // [len=5]["ABCDE"][len=7]["1234567"]
    std::vector<uint8_t> bytes = {
        0x05, 0x00, 0x00, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x07, 0x00, 0x00, 0x00, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes));

    const auto first = buffer.getElement(0);
    const auto second = buffer.getElement(1);

    ASSERT_EQ(first.size(), 5u);
    ASSERT_EQ(second.size(), 7u);
    EXPECT_EQ(first[0], 0x41);
    EXPECT_EQ(first[4], 0x45);
    EXPECT_EQ(second[0], 0x31);
    EXPECT_EQ(second[6], 0x37);
}

TEST(ByteBufferTest, GetElement_OutOfRange_Throws) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04};
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes), 2);
    EXPECT_THROW((void)buffer.getElement(2), InvalidInputException);
}

TEST(ByteBufferTest, ConstructWithNumElements_FixedSize_AllocatesAndSets) {
    ByteBufferTestProxy buffer(3u, 2u);
    EXPECT_EQ(buffer.GetNumElements(), 3u);
    EXPECT_TRUE(buffer.GetHasFixedSizedElements());
    EXPECT_EQ(buffer.GetElementSize(), 2u);
    EXPECT_TRUE(buffer.GetOffsets().empty());

    std::vector<uint8_t> first = {0xAA, 0xBB};
    std::vector<uint8_t> third = {0xCC, 0xDD};
    buffer.setElement(0, tcb::span<const uint8_t>(first));
    buffer.setElement(2, tcb::span<const uint8_t>(third));

    const auto read_first = buffer.getElement(0);
    const auto read_third = buffer.getElement(2);
    ASSERT_EQ(read_first.size(), 2u);
    ASSERT_EQ(read_third.size(), 2u);
    EXPECT_EQ(read_first[0], 0xAA);
    EXPECT_EQ(read_first[1], 0xBB);
    EXPECT_EQ(read_third[0], 0xCC);
    EXPECT_EQ(read_third[1], 0xDD);
}

TEST(ByteBufferTest, ConstructWithNumElements_VariableSize_AllocatesAndSets) {
    ByteBufferTestProxy buffer(2u, 8u, true);
    EXPECT_EQ(buffer.GetNumElements(), 2u);
    EXPECT_FALSE(buffer.GetHasFixedSizedElements());
    EXPECT_EQ(buffer.GetElementSize(), 0u);
    ASSERT_EQ(buffer.GetOffsets().size(), 2u);
    EXPECT_EQ(buffer.GetOffsets()[0], 0u);
    EXPECT_EQ(buffer.GetOffsets()[1], 4u);

    std::vector<uint8_t> first = {0x10, 0x11, 0x12, 0x13, 0x14};
    std::vector<uint8_t> second = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26};
    buffer.setElement(0, tcb::span<const uint8_t>(first));
    buffer.setElement(1, tcb::span<const uint8_t>(second));

    const auto read_first = buffer.getElement(0);
    const auto read_second = buffer.getElement(1);
    ASSERT_EQ(read_first.size(), first.size());
    ASSERT_EQ(read_second.size(), second.size());
    EXPECT_EQ(read_first[0], 0x10);
    EXPECT_EQ(read_first[4], 0x14);
    EXPECT_EQ(read_second[0], 0x20);
    EXPECT_EQ(read_second[6], 0x26);
}

TEST(ByteBufferTest, SetElement_FixedSize_WrongPayloadSize_Throws) {
    ByteBufferTestProxy buffer(1u, 4u);
    std::vector<uint8_t> wrong = {0x01, 0x02};
    EXPECT_THROW((void)buffer.setElement(0, tcb::span<const uint8_t>(wrong)), InvalidInputException);
}

TEST(ByteBufferTest, SetElement_OnReadOnlyBuffer_Throws) {
    std::vector<uint8_t> bytes = {0x10, 0x11, 0x20, 0x21};
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes), 2);
    std::vector<uint8_t> replacement = {0xAA, 0xBB};
    EXPECT_THROW((void)buffer.setElement(0, tcb::span<const uint8_t>(replacement)), InvalidInputException);
}

TEST(ByteBufferTest, ConstructVariableSize_EmptyBuffer_InitializesEmptyState) {
    std::vector<uint8_t> bytes;
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes));
    ExpectCommonState(buffer, 0u, false, 0u);
    EXPECT_TRUE(buffer.GetOffsets().empty());
}

TEST(ByteBufferTest, ConstructVariableSize_TruncatedLengthPrefix_Throws) {
    std::vector<uint8_t> bytes = {0x01, 0x00, 0x00}; // only 3 bytes
    EXPECT_THROW((void)ByteBufferTestProxy(tcb::span<const uint8_t>(bytes)), InvalidInputException);
}

TEST(ByteBufferTest, ConstructVariableSize_TruncatedPayload_Throws) {
    // Declares payload length 5, but provides only 2 bytes.
    std::vector<uint8_t> bytes = {
        0x05, 0x00, 0x00, 0x00, 0xAA, 0xBB
    };
    EXPECT_THROW((void)ByteBufferTestProxy(tcb::span<const uint8_t>(bytes)), InvalidInputException);
}
