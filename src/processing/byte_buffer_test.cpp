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

#include "bytes_utils.h"
#include "exceptions.h"

using dbps::processing::ByteBuffer;
using dbps::processing::kUnsetVariableElementOffset;

class ByteBufferTestProxy : public ByteBuffer {
public:
    ByteBufferTestProxy(
        tcb::span<const uint8_t> elements_span)
        : ByteBuffer(elements_span) {}
    ByteBufferTestProxy(
        tcb::span<const uint8_t> elements_span,
        size_t element_size,
        size_t prefix_size = 0)
        : ByteBuffer(elements_span, element_size, prefix_size) {}
    ByteBufferTestProxy(size_t num_elements)
        : ByteBuffer(num_elements, 0, false) {}
    ByteBufferTestProxy(
        size_t num_elements,
        size_t reserved_bytes_hint,
        bool use_reserve_hint,
        size_t prefix_size = 0)
        : ByteBuffer(num_elements, reserved_bytes_hint, use_reserve_hint, prefix_size) {}
    ByteBufferTestProxy(size_t num_elements, size_t element_size, size_t prefix_size = 0)
        : ByteBuffer(num_elements, element_size, prefix_size) {}
    using ByteBuffer::EstimateOffsetsReserveCountFromSample;

    size_t GetNumElements() const { return num_elements_; }
    bool GetHasFixedSizedElements() const { return has_fixed_sized_elements_; }
    size_t GetElementSize() const { return element_size_; }
    const std::vector<size_t>& GetOffsets() const { return offsets_; }
    const std::vector<uint8_t>& GetWriteBuffer() const { return write_buffer_; }
    void SetWriteBufferByteForTest(size_t idx, uint8_t value) {
        write_buffer_[idx] = value;
    }
    void AppendTrailingBytesForTest(tcb::span<const uint8_t> bytes) {
        write_buffer_.insert(write_buffer_.end(), bytes.begin(), bytes.end());
    }
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

std::vector<uint8_t> MakePayload(size_t size, uint8_t seed) {
    std::vector<uint8_t> payload(size);
    for (size_t i = 0; i < size; ++i) {
        payload[i] = static_cast<uint8_t>(seed + static_cast<uint8_t>(i));
    }
    return payload;
}

} // namespace

TEST(ByteBufferTest, ConstructFixedSize_ValidBuffer_InitializesExpectedState) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes), 2);
    // Trigger lazy span initialization.
    EXPECT_NO_THROW((void)buffer.GetElement(0));
    ExpectCommonState(buffer, 3u, true, 2u);
    EXPECT_TRUE(buffer.GetOffsets().empty());
}

TEST(ByteBufferTest, GetElement_FixedSize_ReturnsExpectedSlices) {
    std::vector<uint8_t> bytes = {0x10, 0x11, 0x20, 0x21, 0x30, 0x31};
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes), 2);

    const auto first = buffer.GetElement(0);
    const auto second = buffer.GetElement(1);
    const auto third = buffer.GetElement(2);

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

TEST(ByteBufferTest, GetElement_FixedSize_WithPrefixSize_SkipsPrefix) {
    std::vector<uint8_t> bytes = {
        0xFE, 0xFD, 0xFC, // prefix
        0x10, 0x11, 0x20, 0x21, 0x30, 0x31
    };
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes), 2u, 3u);

    const auto first = buffer.GetElement(0);
    const auto second = buffer.GetElement(1);
    const auto third = buffer.GetElement(2);

    EXPECT_EQ(std::vector<uint8_t>(first.begin(), first.end()), (std::vector<uint8_t>{0x10, 0x11}));
    EXPECT_EQ(std::vector<uint8_t>(second.begin(), second.end()), (std::vector<uint8_t>{0x20, 0x21}));
    EXPECT_EQ(std::vector<uint8_t>(third.begin(), third.end()), (std::vector<uint8_t>{0x30, 0x31}));
}

TEST(ByteBufferTest, GetElement_VariableSize_WithPrefixSize_SkipsPrefix) {
    std::vector<uint8_t> bytes = {
        0xEE, 0xDD, // prefix
        0x02, 0x00, 0x00, 0x00, 0x41, 0x42,
        0x03, 0x00, 0x00, 0x00, 0x78, 0x79, 0x7A
    };
    ByteBuffer buffer(tcb::span<const uint8_t>(bytes), 2u);

    const auto first = buffer.GetElement(0);
    const auto second = buffer.GetElement(1);

    EXPECT_EQ(std::vector<uint8_t>(first.begin(), first.end()), (std::vector<uint8_t>{0x41, 0x42}));
    EXPECT_EQ(std::vector<uint8_t>(second.begin(), second.end()), (std::vector<uint8_t>{0x78, 0x79, 0x7A}));
}

TEST(ByteBufferTest, ConstructFixedSize_ZeroElementSize_Throws) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04};
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes), 0);
    EXPECT_THROW((void)buffer.GetElement(0), InvalidInputException);
}

TEST(ByteBufferTest, ConstructFixedSize_NonDivisibleSize_Throws) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes), 2);
    EXPECT_THROW((void)buffer.GetElement(0), InvalidInputException);
}

TEST(ByteBufferTest, ConstructVariableSize_ValidEncodedBuffer_InitializesExpectedState) {
    // [len=5]["ABCDE"][len=7]["1234567"]
    std::vector<uint8_t> bytes = {
        0x05, 0x00, 0x00, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x07, 0x00, 0x00, 0x00, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
    ByteBufferTestProxy buffer{tcb::span<const uint8_t>(bytes)};
    // Trigger lazy variable-size index parsing.
    EXPECT_NO_THROW((void)buffer.GetElement(0));
    ExpectCommonState(buffer, 2u, false, 0u);
    ASSERT_EQ(buffer.GetOffsets().size(), 2u);
    EXPECT_EQ(buffer.GetOffsets()[0], 0u);
    EXPECT_EQ(buffer.GetOffsets()[1], 9u);  // 4 bytes length prefix + 5 bytes first payload.
}

TEST(ByteBufferTest, EstimateOffsetsReserveCountFromSample_MultipleCases) {
    const auto make_variable_size_bytes = [](const std::vector<size_t>& sizes) {
        std::vector<uint8_t> bytes;
        for (size_t idx = 0; idx < sizes.size(); ++idx) {
            append_u32_le(bytes, static_cast<uint32_t>(sizes[idx]));
            for (size_t j = 0; j < sizes[idx]; ++j) {
                bytes.push_back(static_cast<uint8_t>((idx + j) & 0xFF));
            }
        }
        return bytes;
    };

    // Empty buffer.
    {
        const std::vector<size_t> sizes = {};
        const std::vector<uint8_t> bytes = make_variable_size_bytes(sizes);
        const size_t estimated = ByteBufferTestProxy::EstimateOffsetsReserveCountFromSample(tcb::span<const uint8_t>(bytes));
        EXPECT_EQ(estimated, 0u);
    }

    // Buffer with less than sample size (5 vs 10): exact count, no extrapolation/headroom needed.
    {
        const std::vector<size_t> sizes = {1u, 2u, 50u, 4u, 7u};
        const std::vector<uint8_t> bytes = make_variable_size_bytes(sizes);
        const size_t estimated = ByteBufferTestProxy::EstimateOffsetsReserveCountFromSample(tcb::span<const uint8_t>(bytes));
        EXPECT_EQ(estimated, sizes.size());
    }

    // Buffer with uniform record sizes. Base estimate is exact, then +10% headroom is applied.
    {
        // 30 elements, each 6 bytes long.
        const size_t num_elements = 30u;
        const size_t payload_size = 6u;
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < num_elements; ++i) {
            append_u32_le(bytes, static_cast<uint32_t>(payload_size));
            for (size_t j = 0; j < payload_size; ++j) {
                bytes.push_back(static_cast<uint8_t>((i + j) & 0xFF));
            }
        }
        const size_t estimate = ByteBufferTestProxy::EstimateOffsetsReserveCountFromSample(tcb::span<const uint8_t>(bytes));
        EXPECT_EQ(estimate, 33u);  //33 = 30 elements + 10% headroom.
    }

    // Buffer to estimate intentionally overshoots the true element count.
    {
        // First 10 elements are very small, tail elements are very large:
        const std::vector<size_t> sizes = {1u, 1u, 1u, 1u, 1u, 1u, 1u, 1u, 1u, 1u, 100u, 100u};
        const std::vector<uint8_t> bytes = make_variable_size_bytes(sizes);
        const size_t estimate = ByteBufferTestProxy::EstimateOffsetsReserveCountFromSample(tcb::span<const uint8_t>(bytes));
        EXPECT_GT(estimate, sizes.size());
    }
}

TEST(ByteBufferTest, GetElement_VariableSize_ReturnsExpectedPayload) {
    // [len=5]["ABCDE"][len=7]["1234567"]
    std::vector<uint8_t> bytes = {
        0x05, 0x00, 0x00, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x07, 0x00, 0x00, 0x00, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
    ByteBufferTestProxy buffer{tcb::span<const uint8_t>(bytes)};

    const auto first = buffer.GetElement(0);
    const auto second = buffer.GetElement(1);

    ASSERT_EQ(first.size(), 5u);
    ASSERT_EQ(second.size(), 7u);
    EXPECT_EQ(first[0], 0x41);
    EXPECT_EQ(first[4], 0x45);
    EXPECT_EQ(second[0], 0x31);
    EXPECT_EQ(second[6], 0x37);
}

TEST(ByteBufferTest, Iterate_ReadOnlyVariableSize_WithPrefixSize_SkipsPrefix) {
    std::vector<uint8_t> bytes = {
        0xEE, 0xDD, // prefix
        0x02, 0x00, 0x00, 0x00, 0x41, 0x42,
        0x03, 0x00, 0x00, 0x00, 0x78, 0x79, 0x7A
    };
    ByteBuffer buffer(tcb::span<const uint8_t>(bytes), 2u);

    std::vector<std::vector<uint8_t>> collected;
    for (const auto element : buffer) {
        collected.push_back(std::vector<uint8_t>(element.begin(), element.end()));
    }

    ASSERT_EQ(collected.size(), 2u);
    EXPECT_EQ(collected[0], (std::vector<uint8_t>{0x41, 0x42}));
    EXPECT_EQ(collected[1], (std::vector<uint8_t>{0x78, 0x79, 0x7A}));
}

TEST(ByteBufferTest, Iterate_ReadOnlyFixedSize_WithPrefixSize_SkipsPrefix) {
    std::vector<uint8_t> bytes = {
        0xFE, 0xFD, 0xFC, // prefix
        0x10, 0x11, 0x20, 0x21, 0x30, 0x31
    };
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes), 2u, 3u);

    std::vector<std::vector<uint8_t>> collected;
    for (const auto element : buffer) {
        collected.push_back(std::vector<uint8_t>(element.begin(), element.end()));
    }

    ASSERT_EQ(collected.size(), 3u);
    EXPECT_EQ(collected[0], (std::vector<uint8_t>{0x10, 0x11}));
    EXPECT_EQ(collected[1], (std::vector<uint8_t>{0x20, 0x21}));
    EXPECT_EQ(collected[2], (std::vector<uint8_t>{0x30, 0x31}));
}

TEST(ByteBufferTest, Iterate_ReadOnlyFixedSize_TraversesInOrder) {
    std::vector<uint8_t> bytes = {0x10, 0x11, 0x20, 0x21, 0x30, 0x31};
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes), 2);

    std::vector<std::vector<uint8_t>> collected;
    for (const auto element : buffer) {
        collected.push_back(std::vector<uint8_t>(element.begin(), element.end()));
    }

    ASSERT_EQ(collected.size(), 3u);
    EXPECT_EQ(collected[0], (std::vector<uint8_t>{0x10, 0x11}));
    EXPECT_EQ(collected[1], (std::vector<uint8_t>{0x20, 0x21}));
    EXPECT_EQ(collected[2], (std::vector<uint8_t>{0x30, 0x31}));

    // Check InitializeFromSpan was not called yet.
    EXPECT_TRUE(buffer.GetOffsets().empty());
    EXPECT_EQ(buffer.GetNumElements(), 0);

    // Now read the elemennts through GetElement. It calls the InitializeFromSpan method.
    std::vector<std::vector<uint8_t>> collected_with_get_element;
    for (size_t i = 0; i < collected.size(); ++i) {
        const auto element = buffer.GetElement(i);
        collected_with_get_element.push_back(std::vector<uint8_t>(element.begin(), element.end()));
    }

    // Check elements read with GetElement are the same as the ones collected with the iterator.
    EXPECT_EQ(collected_with_get_element, collected);

    // Offsets should still be empty after the iteration because these fixed-size elements.
    // However, the number of elements is now known.
    EXPECT_TRUE(buffer.GetOffsets().empty());
    EXPECT_EQ(buffer.GetNumElements(), 3u);

}

TEST(ByteBufferTest, Iterate_ReadOnlyVariableSize_TraversesInOrder) {
    // [len=5]["ABCDE"][len=7]["1234567"]
    std::vector<uint8_t> bytes = {
        0x05, 0x00, 0x00, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x07, 0x00, 0x00, 0x00, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
    ByteBufferTestProxy buffer{tcb::span<const uint8_t>(bytes)};

    std::vector<std::vector<uint8_t>> collected;
    for (const auto element : buffer) {
        collected.push_back(std::vector<uint8_t>(element.begin(), element.end()));
    }

    ASSERT_EQ(collected.size(), 2u);
    EXPECT_EQ(collected[0], (std::vector<uint8_t>{0x41, 0x42, 0x43, 0x44, 0x45}));
    EXPECT_EQ(collected[1], (std::vector<uint8_t>{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}));
    
    // Check InitializeFromSpan was not called yet.
    EXPECT_TRUE(buffer.GetOffsets().empty());
    EXPECT_EQ(buffer.GetNumElements(), 0);

    // Now read the elemennts through GetElement. It calls the InitializeFromSpan method.
    std::vector<std::vector<uint8_t>> collected_with_get_element;
    for (size_t i = 0; i < collected.size(); ++i) {
        const auto element = buffer.GetElement(i);
        collected_with_get_element.push_back(std::vector<uint8_t>(element.begin(), element.end()));
    }

    // Check elements read with GetElement are the same as the ones collected with the iterator.
    EXPECT_EQ(collected_with_get_element, collected);

    // Offsets and number of elements should now be initialized.
    ASSERT_EQ(buffer.GetOffsets().size(), 2u);
    EXPECT_EQ(buffer.GetOffsets()[0], 0u);
    EXPECT_EQ(buffer.GetOffsets()[1], 9u); // 4 bytes length prefix + 5 bytes first payload.
    EXPECT_EQ(buffer.GetNumElements(), 2u);

}

TEST(ByteBufferTest, TransformFixedSize_ReadIterateWriteFinalize_RoundTrip) {
    constexpr size_t kElementSize = 2u;
    std::vector<uint8_t> source_bytes = {
        0x10, 0x11,
        0x20, 0x21,
        0x30, 0x31
    };

    // Create a source buffer to read the elements from.
    ByteBufferTestProxy source_buffer(tcb::span<const uint8_t>(source_bytes), kElementSize);

    // Create a new buffer to write the transformed elements.
    ByteBufferTestProxy transformed_buffer(3u, kElementSize);
    size_t position = 0;
    for (const auto element : source_buffer) {
        std::vector<uint8_t> source_element(element.begin(), element.end());
        std::vector<uint8_t> transformed_element = source_element;
        transformed_element[0] = static_cast<uint8_t>(transformed_element[0] + 1u);
        transformed_buffer.SetElement(position, tcb::span<const uint8_t>(transformed_element));
        ++position;
    }

    ASSERT_EQ(position, 3u);

    // Compare source and transformed buffers before finalization.
    for (size_t i = 0; i < position; ++i) {
        const auto source_element = source_buffer.GetElement(i);
        const auto transformed_element = transformed_buffer.GetElement(i);

        std::vector<uint8_t> expected_transformed(source_element.begin(), source_element.end());
        expected_transformed[0] = static_cast<uint8_t>(expected_transformed[0] + 1u);

        EXPECT_EQ(std::vector<uint8_t>(transformed_element.begin(), transformed_element.end()), expected_transformed);
        // Check that transformed element differs from source after applying the mutation.
        EXPECT_NE(std::vector<uint8_t>(source_element.begin(), source_element.end()),
                  std::vector<uint8_t>(transformed_element.begin(), transformed_element.end()));
    }

    // Now finalize the transformed buffer and populate a third buffer to read the elements from.
    std::vector<uint8_t> finalized_bytes = transformed_buffer.FinalizeAndTakeBuffer();
    ByteBufferTestProxy finalized_read_buffer(tcb::span<const uint8_t>(finalized_bytes), kElementSize);

    // Compare source and finalized read buffer using the same transformation rule.
    for (size_t i = 0; i < position; ++i) {
        const auto source_element = source_buffer.GetElement(i);
        const auto finalized_element = finalized_read_buffer.GetElement(i);

        std::vector<uint8_t> expected_transformed(source_element.begin(), source_element.end());
        expected_transformed[0] = static_cast<uint8_t>(expected_transformed[0] + 1u);

        EXPECT_EQ(std::vector<uint8_t>(finalized_element.begin(), finalized_element.end()), expected_transformed);
        EXPECT_NE(std::vector<uint8_t>(source_element.begin(), source_element.end()),
                  std::vector<uint8_t>(finalized_element.begin(), finalized_element.end()));
    }
}

TEST(ByteBufferTest, TransformVariableSize_ReadIterateWriteFinalize_RoundTrip) {
    std::vector<uint8_t> source_bytes;
    append_u32_le(source_bytes, 5u);
    source_bytes.insert(source_bytes.end(), {0x41, 0x42, 0x43, 0x44, 0x45});  // "ABCDE"
    append_u32_le(source_bytes, 7u);
    source_bytes.insert(source_bytes.end(), {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37});  // "1234567"
    append_u32_le(source_bytes, 3u);
    source_bytes.insert(source_bytes.end(), {0x61, 0x62, 0x63});  // "abc"

    ByteBufferTestProxy source_buffer{tcb::span<const uint8_t>(source_bytes)};
    ByteBufferTestProxy transformed_buffer(3u, source_bytes.size(), true);
    size_t position = 0;

    for (const auto element : source_buffer) {
        std::vector<uint8_t> source_element(element.begin(), element.end());
        std::vector<uint8_t> transformed_element = source_element;
        transformed_element[0] = static_cast<uint8_t>(transformed_element[0] + 1u);
        transformed_buffer.SetElement(position, tcb::span<const uint8_t>(transformed_element));
        ++position;
    }

    ASSERT_EQ(position, 3u);

    // Compare source and transformed buffers before finalization.
    for (size_t i = 0; i < position; ++i) {
        const auto source_element = source_buffer.GetElement(i);
        const auto transformed_element = transformed_buffer.GetElement(i);

        std::vector<uint8_t> expected_transformed(source_element.begin(), source_element.end());
        expected_transformed[0] = static_cast<uint8_t>(expected_transformed[0] + 1u);

        EXPECT_EQ(std::vector<uint8_t>(transformed_element.begin(), transformed_element.end()), expected_transformed);
        EXPECT_NE(std::vector<uint8_t>(source_element.begin(), source_element.end()),
                  std::vector<uint8_t>(transformed_element.begin(), transformed_element.end()));
    }

    std::vector<uint8_t> finalized_bytes = transformed_buffer.FinalizeAndTakeBuffer();
    ByteBufferTestProxy finalized_read_buffer{tcb::span<const uint8_t>(finalized_bytes)};

    // Compare source and finalized read buffer using the same transformation rule.
    for (size_t i = 0; i < position; ++i) {
        const auto source_element = source_buffer.GetElement(i);
        const auto finalized_element = finalized_read_buffer.GetElement(i);

        std::vector<uint8_t> expected_transformed(source_element.begin(), source_element.end());
        expected_transformed[0] = static_cast<uint8_t>(expected_transformed[0] + 1u);

        EXPECT_EQ(std::vector<uint8_t>(finalized_element.begin(), finalized_element.end()), expected_transformed);
        EXPECT_NE(std::vector<uint8_t>(source_element.begin(), source_element.end()),
                  std::vector<uint8_t>(finalized_element.begin(), finalized_element.end()));
    }
}

TEST(ByteBufferTest, Iterate_ReadOnlyEmptySpan_VisitsNoElements) {
    std::vector<uint8_t> empty_bytes;

    // Fixed-size empty span.
    ByteBufferTestProxy fixed_buffer(tcb::span<const uint8_t>(empty_bytes), 2);
    size_t fixed_count = 0;
    for (const auto element : fixed_buffer) {
        (void)element;
        ++fixed_count;
    }
    EXPECT_EQ(fixed_count, 0u);

    // Variable-size empty span.
    ByteBufferTestProxy variable_buffer{tcb::span<const uint8_t>(empty_bytes)};
    size_t variable_count = 0;
    for (const auto element : variable_buffer) {
        (void)element;
        ++variable_count;
    }
    EXPECT_EQ(variable_count, 0u);
}

TEST(ByteBufferTest, GetElement_OutOfRange_Throws) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04};
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes), 2);
    EXPECT_THROW((void)buffer.GetElement(2), InvalidInputException);
}

TEST(ByteBufferTest, ConstructWithNumElements_FixedSize_AllocatesAndSets) {
    ByteBufferTestProxy buffer(3u, 2u);
    EXPECT_EQ(buffer.GetNumElements(), 3u);
    EXPECT_TRUE(buffer.GetHasFixedSizedElements());
    EXPECT_EQ(buffer.GetElementSize(), 2u);
    EXPECT_TRUE(buffer.GetOffsets().empty());

    std::vector<uint8_t> first = {0xAA, 0xBB};
    std::vector<uint8_t> third = {0xCC, 0xDD};
    buffer.SetElement(0, tcb::span<const uint8_t>(first));
    buffer.SetElement(2, tcb::span<const uint8_t>(third));

    const auto read_first = buffer.GetElement(0);
    const auto read_third = buffer.GetElement(2);
    ASSERT_EQ(read_first.size(), 2u);
    ASSERT_EQ(read_third.size(), 2u);
    EXPECT_EQ(read_first[0], 0xAA);
    EXPECT_EQ(read_first[1], 0xBB);
    EXPECT_EQ(read_third[0], 0xCC);
    EXPECT_EQ(read_third[1], 0xDD);
}

TEST(ByteBufferTest, ConstructWithNumElements_FixedSize_WithPrefixSize_PreservesLeadingBytes) {
    ByteBufferTestProxy buffer(2u, 3u, (size_t) 7u);

    std::vector<uint8_t> first = {0xAA, 0xBB, 0xBC};
    std::vector<uint8_t> second = {0xCC, 0xDD, 0xDE};

    // Write elements out of order to trigger the defragmentation path.
    buffer.SetElement(1, tcb::span<const uint8_t>(second));
    buffer.SetElement(0, tcb::span<const uint8_t>(first));

    // Manually annotate prefix bytes and verify they are preserved after finalize.
    buffer.SetWriteBufferByteForTest(0u, 0xF0);
    buffer.SetWriteBufferByteForTest(1u, 0x0D);
    buffer.SetWriteBufferByteForTest(2u, 0xBE);


    std::vector<uint8_t> final_buffer = buffer.FinalizeAndTakeBuffer();
    ASSERT_EQ(final_buffer.size(), 13u);
    EXPECT_EQ(final_buffer[0], 0xF0);
    EXPECT_EQ(final_buffer[1], 0x0D);
    EXPECT_EQ(final_buffer[2], 0xBE);
    EXPECT_EQ(final_buffer[7], 0xAA);
    EXPECT_EQ(final_buffer[8], 0xBB);
    EXPECT_EQ(final_buffer[9], 0xBC);
    EXPECT_EQ(final_buffer[10], 0xCC);
    EXPECT_EQ(final_buffer[11], 0xDD);
    EXPECT_EQ(final_buffer[12], 0xDE);
}

TEST(ByteBufferTest, ConstructWithNumElements_VariableSize_AllocatesAndSets) {
    ByteBufferTestProxy buffer(2u, 8u, true);
    EXPECT_EQ(buffer.GetNumElements(), 2u);
    EXPECT_FALSE(buffer.GetHasFixedSizedElements());
    EXPECT_EQ(buffer.GetElementSize(), 0u);
    ASSERT_EQ(buffer.GetOffsets().size(), 2u);
    EXPECT_EQ(buffer.GetOffsets()[0], kUnsetVariableElementOffset);
    EXPECT_EQ(buffer.GetOffsets()[1], kUnsetVariableElementOffset);

    std::vector<uint8_t> first = {0x10, 0x11, 0x12, 0x13, 0x14};
    std::vector<uint8_t> second = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26};
    buffer.SetElement(0, tcb::span<const uint8_t>(first));
    buffer.SetElement(1, tcb::span<const uint8_t>(second));

    const auto read_first = buffer.GetElement(0);
    const auto read_second = buffer.GetElement(1);
    ASSERT_EQ(read_first.size(), first.size());
    ASSERT_EQ(read_second.size(), second.size());
    EXPECT_EQ(read_first[0], 0x10);
    EXPECT_EQ(read_first[4], 0x14);
    EXPECT_EQ(read_second[0], 0x20);
    EXPECT_EQ(read_second[6], 0x26);
}

TEST(ByteBufferTest, ConstructWithNumElements_VariableSize_WithPrefixSize_PreservesLeadingBytes) {
    size_t prefix_size = 3u;
    ByteBufferTestProxy buffer(2u, 8u, true, prefix_size);

    std::vector<uint8_t> first = {0x10, 0x11};
    std::vector<uint8_t> second = {0x20, 0x21, 0x22, 0x23, 0x24};

    // Write elements out of order to trigger the defragmentation path.
    buffer.SetElement(1, tcb::span<const uint8_t>(second));
    buffer.SetElement(0, tcb::span<const uint8_t>(first));

    // Manually annotate prefix bytes and verify they are preserved after finalize.
    buffer.SetWriteBufferByteForTest(0u, 0xF0);
    buffer.SetWriteBufferByteForTest(1u, 0x0D);
    buffer.SetWriteBufferByteForTest(2u, 0xBE);

    std::vector<uint8_t> final_buffer = buffer.FinalizeAndTakeBuffer();
    ASSERT_EQ(final_buffer.size(), prefix_size + 4 + first.size() + 4 + second.size());
    EXPECT_EQ(final_buffer[0], 0xF0);
    EXPECT_EQ(final_buffer[1], 0x0D);
    EXPECT_EQ(final_buffer[2], 0xBE);

    // First record starts right after the configured prefix_size.
    EXPECT_EQ(read_u32_le(final_buffer, prefix_size), first.size());
    EXPECT_EQ(final_buffer[7], 0x10);
    EXPECT_EQ(final_buffer[8], 0x11);

    // Second record follows contiguously.
    EXPECT_EQ(read_u32_le(final_buffer, prefix_size + 4 + first.size()), second.size());
    EXPECT_EQ(final_buffer[13], 0x20);
    EXPECT_EQ(final_buffer[14], 0x21);
    EXPECT_EQ(final_buffer[15], 0x22);
    EXPECT_EQ(final_buffer[16], 0x23);
    EXPECT_EQ(final_buffer[17], 0x24);
}

TEST(ByteBufferTest, GetElement_VariableSize_UnsetPosition_Throws) {
    ByteBufferTestProxy buffer(2u, 8u, true);
    std::vector<uint8_t> second = {0x20, 0x21, 0x22};
    buffer.SetElement(1, tcb::span<const uint8_t>(second));

    EXPECT_THROW((void)buffer.GetElement(0), InvalidInputException);
}

TEST(ByteBufferTest, SetElement_VariableSize_OutOfOrderAndOverwrite_ReturnsLatestValues) {
    ByteBufferTestProxy buffer(3u, 32u, true);

    std::vector<uint8_t> v2_first = {0xA0, 0xA1};
    std::vector<uint8_t> v0_first = {0xB0, 0xB1, 0xB2};
    std::vector<uint8_t> v1_first = {0xC0};
    std::vector<uint8_t> v0_second = {0xD0, 0xD1, 0xD2, 0xD3};
    std::vector<uint8_t> v2_second = {0xE0, 0xE1, 0xE2};

    // Write in non-sequential order.
    buffer.SetElement(2, tcb::span<const uint8_t>(v2_first));
    buffer.SetElement(0, tcb::span<const uint8_t>(v0_first));
    buffer.SetElement(1, tcb::span<const uint8_t>(v1_first));

    const auto e0_before = buffer.GetElement(0);
    const auto e1_before = buffer.GetElement(1);
    const auto e2_before = buffer.GetElement(2);
    ASSERT_EQ(e0_before.size(), v0_first.size());
    ASSERT_EQ(e1_before.size(), v1_first.size());
    ASSERT_EQ(e2_before.size(), v2_first.size());
    for (size_t i = 0; i < v0_first.size(); ++i) {
        EXPECT_EQ(e0_before[i], v0_first[i]);
    }
    for (size_t i = 0; i < v1_first.size(); ++i) {
        EXPECT_EQ(e1_before[i], v1_first[i]);
    }
    for (size_t i = 0; i < v2_first.size(); ++i) {
        EXPECT_EQ(e2_before[i], v2_first[i]);
    }

    const size_t offset0_before_overwrite = buffer.GetOffsets()[0];
    const size_t offset2_before_overwrite = buffer.GetOffsets()[2];

    // Overwrite previously written positions; latest append should win.
    buffer.SetElement(0, tcb::span<const uint8_t>(v0_second));
    buffer.SetElement(2, tcb::span<const uint8_t>(v2_second));

    const size_t expected_write_buffer_size =
        (4u + v2_first.size()) +
        (4u + v0_first.size()) +
        (4u + v1_first.size()) +
        (4u + v0_second.size()) +
        (4u + v2_second.size());
    // Check that append-only writes include overwritten records too.
    EXPECT_EQ(buffer.GetWriteBuffer().size(), expected_write_buffer_size);

    EXPECT_GT(buffer.GetOffsets()[0], offset0_before_overwrite);
    EXPECT_GT(buffer.GetOffsets()[2], offset2_before_overwrite);

    const auto e0 = buffer.GetElement(0);
    const auto e1 = buffer.GetElement(1);
    const auto e2 = buffer.GetElement(2);

    ASSERT_EQ(e0.size(), v0_second.size());
    ASSERT_EQ(e1.size(), v1_first.size());
    ASSERT_EQ(e2.size(), v2_second.size());

    for (size_t i = 0; i < v0_second.size(); ++i) {
        EXPECT_EQ(e0[i], v0_second[i]);
    }
    for (size_t i = 0; i < v1_first.size(); ++i) {
        EXPECT_EQ(e1[i], v1_first[i]);
    }
    for (size_t i = 0; i < v2_second.size(); ++i) {
        EXPECT_EQ(e2[i], v2_second[i]);
    }
}

TEST(ByteBufferTest, VariableSizeWrite_ExactHint_NoReallocationAndExactUsedSize) {
    const std::vector<size_t> payload_sizes = {37u, 11u, 47u, 23u, 43u, 17u, 31u};
    const size_t num_elements = payload_sizes.size();

    size_t total_payload_bytes = 0;
    for (size_t size : payload_sizes) {
        total_payload_bytes += size;
    }
    const size_t exact_hint_bytes = (num_elements * 4u) + total_payload_bytes;

    ByteBufferTestProxy buffer(num_elements, exact_hint_bytes, true);
    const size_t initial_capacity = buffer.GetWriteBuffer().capacity();
    const uint8_t* const initial_data_ptr = buffer.GetWriteBuffer().data();

    std::vector<std::vector<uint8_t>> payloads;
    payloads.reserve(num_elements);
    for (size_t i = 0; i < num_elements; ++i) {
        payloads.push_back(MakePayload(payload_sizes[i], static_cast<uint8_t>(0x10 + i)));
        buffer.SetElement(i, tcb::span<const uint8_t>(payloads.back()));
    }

    EXPECT_EQ(buffer.GetWriteBuffer().size(), exact_hint_bytes);
    EXPECT_EQ(buffer.GetWriteBuffer().capacity(), initial_capacity);
    EXPECT_EQ(buffer.GetWriteBuffer().capacity(), exact_hint_bytes);
    EXPECT_EQ(buffer.GetWriteBuffer().data(), initial_data_ptr);

    for (size_t i = 0; i < num_elements; ++i) {
        const auto value = buffer.GetElement(i);
        ASSERT_EQ(value.size(), payloads[i].size());
        for (size_t j = 0; j < payloads[i].size(); ++j) {
            EXPECT_EQ(value[j], payloads[i][j]);
        }
    }

    const uint8_t* const data_ptr_before_finalize = buffer.GetWriteBuffer().data();
    std::vector<uint8_t> final_buffer = buffer.FinalizeAndTakeBuffer();
    EXPECT_EQ(final_buffer.data(), data_ptr_before_finalize);  // Same allocation: finalize returned write_buffer_ as-is.
}

TEST(ByteBufferTest, VariableSizeWrite_ExceedsHint_ReallocatesBuffer) {
    const size_t num_elements = 7u;
    ByteBufferTestProxy buffer(num_elements, 32u, true);

    const size_t initial_capacity = buffer.GetWriteBuffer().capacity();
    const uint8_t* const initial_data_ptr = buffer.GetWriteBuffer().data();

    std::vector<std::vector<uint8_t>> payloads;
    payloads.reserve(num_elements);
    for (size_t i = 0; i < num_elements; ++i) {
        payloads.push_back(MakePayload(64u + (i * 9u), static_cast<uint8_t>(0x40 + i)));
        buffer.SetElement(i, tcb::span<const uint8_t>(payloads.back()));
    }

    EXPECT_GT(buffer.GetWriteBuffer().size(), initial_capacity);
    EXPECT_GT(buffer.GetWriteBuffer().capacity(), initial_capacity);
    EXPECT_NE(buffer.GetWriteBuffer().data(), initial_data_ptr);

    for (size_t i = 0; i < num_elements; ++i) {
        const auto value = buffer.GetElement(i);
        ASSERT_EQ(value.size(), payloads[i].size());
        for (size_t j = 0; j < payloads[i].size(); ++j) {
            EXPECT_EQ(value[j], payloads[i][j]);
        }
    }
}

TEST(ByteBufferTest, FinalizeAndTakeBuffer_VariableSize_PartialWrite_ThrowsAndAllowsRetry) {
    ByteBufferTestProxy buffer(2u, 8u, true);
    std::vector<uint8_t> first = {0x10, 0x11};
    std::vector<uint8_t> second = {0x20, 0x21, 0x22};
    buffer.SetElement(1, tcb::span<const uint8_t>(second));

    EXPECT_THROW((void)buffer.FinalizeAndTakeBuffer(), InvalidInputException);

    buffer.SetElement(0, tcb::span<const uint8_t>(first));
    const uint8_t* const data_ptr_before = buffer.GetWriteBuffer().data();
    std::vector<uint8_t> final_buffer = buffer.FinalizeAndTakeBuffer();
    EXPECT_NE(final_buffer.data(), data_ptr_before);  // Different allocation (defragmented after retry).

    ByteBufferTestProxy read_back{tcb::span<const uint8_t>(final_buffer)};
    const auto r0 = read_back.GetElement(0);
    const auto r1 = read_back.GetElement(1);
    ASSERT_EQ(r0.size(), first.size());
    ASSERT_EQ(r1.size(), second.size());
    EXPECT_EQ(r0[0], 0x10);
    EXPECT_EQ(r0[1], 0x11);
    EXPECT_EQ(r1[0], 0x20);
    EXPECT_EQ(r1[2], 0x22);
}

TEST(ByteBufferTest, FinalizeAndTakeBuffer_VariableSize_Sequential_ReturnsAsIs) {
    ByteBufferTestProxy buffer(3u, 64u, true);
    std::vector<uint8_t> first = {0x10, 0x11};
    std::vector<uint8_t> second = {0x20, 0x21, 0x22};
    std::vector<uint8_t> third = {0x30};

    buffer.SetElement(0, tcb::span<const uint8_t>(first));
    buffer.SetElement(1, tcb::span<const uint8_t>(second));
    buffer.SetElement(2, tcb::span<const uint8_t>(third));

    const std::vector<uint8_t> raw_before_finalize = buffer.GetWriteBuffer();
    const uint8_t* const data_ptr_before = buffer.GetWriteBuffer().data();
    std::vector<uint8_t> final_buffer = buffer.FinalizeAndTakeBuffer();

    EXPECT_EQ(final_buffer, raw_before_finalize);     // Same byte content.
    EXPECT_EQ(final_buffer.data(), data_ptr_before);  // Same allocation (moved, not copied).
}

TEST(ByteBufferTest, FinalizeAndTakeBuffer_VariableSize_SequentialWithTrailingBytes_Throws) {
    ByteBufferTestProxy buffer(3u, 64u, true);
    std::vector<uint8_t> first = {0x10, 0x11};
    std::vector<uint8_t> second = {0x20, 0x21, 0x22};
    std::vector<uint8_t> third = {0x30};

    buffer.SetElement(0, tcb::span<const uint8_t>(first));
    buffer.SetElement(1, tcb::span<const uint8_t>(second));
    buffer.SetElement(2, tcb::span<const uint8_t>(third));

    const size_t expected_trimmed_size =
        (4u + first.size()) + (4u + second.size()) + (4u + third.size());

    std::vector<uint8_t> trailing = {0xEE, 0xEF, 0xF0};
    buffer.AppendTrailingBytesForTest(tcb::span<const uint8_t>(trailing));
    EXPECT_EQ(buffer.GetWriteBuffer().size(), expected_trimmed_size + trailing.size());

    EXPECT_THROW((void)buffer.FinalizeAndTakeBuffer(), InvalidInputException);
}

TEST(ByteBufferTest, FinalizeAndTakeBuffer_VariableSize_OutOfOrder_Defragments) {
    ByteBufferTestProxy buffer(3u, 64u, true);
    std::vector<uint8_t> first = {0x10, 0x11};
    std::vector<uint8_t> second = {0x20, 0x21, 0x22};
    std::vector<uint8_t> third = {0x30};

    buffer.SetElement(2, tcb::span<const uint8_t>(third));
    buffer.SetElement(0, tcb::span<const uint8_t>(first));
    buffer.SetElement(1, tcb::span<const uint8_t>(second));

    const std::vector<uint8_t> raw_before_finalize = buffer.GetWriteBuffer();
    const uint8_t* const data_ptr_before = buffer.GetWriteBuffer().data();
    std::vector<uint8_t> final_buffer = buffer.FinalizeAndTakeBuffer();

    EXPECT_NE(final_buffer, raw_before_finalize);     // Different byte content.
    EXPECT_NE(final_buffer.data(), data_ptr_before);  // Different allocation (defragmented copy).

    ByteBufferTestProxy read_back{tcb::span<const uint8_t>(final_buffer)};
    const auto r0 = read_back.GetElement(0);
    const auto r1 = read_back.GetElement(1);
    const auto r2 = read_back.GetElement(2);
    ASSERT_EQ(r0.size(), first.size());
    ASSERT_EQ(r1.size(), second.size());
    ASSERT_EQ(r2.size(), third.size());
    for (size_t i = 0; i < first.size(); ++i) {
        EXPECT_EQ(r0[i], first[i]);
    }
    for (size_t i = 0; i < second.size(); ++i) {
        EXPECT_EQ(r1[i], second[i]);
    }
    for (size_t i = 0; i < third.size(); ++i) {
        EXPECT_EQ(r2[i], third[i]);
    }
}

TEST(ByteBufferTest, FinalizeAndTakeBuffer_VariableSize_Fragmented_Defragments) {
    ByteBufferTestProxy buffer(2u, 64u, true);
    std::vector<uint8_t> first_initial = {0x10, 0x11};
    std::vector<uint8_t> second = {0x20, 0x21, 0x22};
    std::vector<uint8_t> first_overwrite = {0x30, 0x31, 0x32, 0x33};

    buffer.SetElement(0, tcb::span<const uint8_t>(first_initial));
    buffer.SetElement(1, tcb::span<const uint8_t>(second));
    buffer.SetElement(0, tcb::span<const uint8_t>(first_overwrite));

    const size_t raw_size_before_finalize = buffer.GetWriteBuffer().size();
    const std::vector<uint8_t> raw_before_finalize = buffer.GetWriteBuffer();
    const uint8_t* const data_ptr_before = buffer.GetWriteBuffer().data();
    std::vector<uint8_t> final_buffer = buffer.FinalizeAndTakeBuffer();

    EXPECT_LT(final_buffer.size(), raw_size_before_finalize);
    EXPECT_NE(final_buffer, raw_before_finalize);
    EXPECT_NE(final_buffer.data(), data_ptr_before);  // Different allocation (defragmented copy).

    ByteBufferTestProxy read_back{tcb::span<const uint8_t>(final_buffer)};
    const auto r0 = read_back.GetElement(0);
    const auto r1 = read_back.GetElement(1);
    ASSERT_EQ(r0.size(), first_overwrite.size());
    ASSERT_EQ(r1.size(), second.size());
    for (size_t i = 0; i < first_overwrite.size(); ++i) {
        EXPECT_EQ(r0[i], first_overwrite[i]);
    }
    for (size_t i = 0; i < second.size(); ++i) {
        EXPECT_EQ(r1[i], second[i]);
    }
}

TEST(ByteBufferTest, SetElement_FixedSize_OutOfOrderAndOverwrite_ReturnsLatestValues) {
    ByteBufferTestProxy buffer(3u, 2u);

    std::vector<uint8_t> v2_first = {0xA0, 0xA1};
    std::vector<uint8_t> v0_first = {0xB0, 0xB1};
    std::vector<uint8_t> v1_first = {0xC0, 0xC1};
    std::vector<uint8_t> v0_second = {0xD0, 0xD1};
    std::vector<uint8_t> v2_second = {0xE0, 0xE1};

    // Write in non-sequential order.
    buffer.SetElement(2, tcb::span<const uint8_t>(v2_first));
    buffer.SetElement(0, tcb::span<const uint8_t>(v0_first));
    buffer.SetElement(1, tcb::span<const uint8_t>(v1_first));

    const auto e0_before = buffer.GetElement(0);
    const auto e1_before = buffer.GetElement(1);
    const auto e2_before = buffer.GetElement(2);
    ASSERT_EQ(e0_before.size(), 2u);
    ASSERT_EQ(e1_before.size(), 2u);
    ASSERT_EQ(e2_before.size(), 2u);
    EXPECT_EQ(e0_before[0], v0_first[0]);
    EXPECT_EQ(e0_before[1], v0_first[1]);
    EXPECT_EQ(e1_before[0], v1_first[0]);
    EXPECT_EQ(e1_before[1], v1_first[1]);
    EXPECT_EQ(e2_before[0], v2_first[0]);
    EXPECT_EQ(e2_before[1], v2_first[1]);

    // Overwrite previously written positions; latest fixed-size bytes should win.
    buffer.SetElement(0, tcb::span<const uint8_t>(v0_second));
    buffer.SetElement(2, tcb::span<const uint8_t>(v2_second));

    const auto e0 = buffer.GetElement(0);
    const auto e1 = buffer.GetElement(1);
    const auto e2 = buffer.GetElement(2);

    ASSERT_EQ(e0.size(), 2u);
    ASSERT_EQ(e1.size(), 2u);
    ASSERT_EQ(e2.size(), 2u);
    EXPECT_EQ(e0[0], v0_second[0]);
    EXPECT_EQ(e0[1], v0_second[1]);
    EXPECT_EQ(e1[0], v1_first[0]);
    EXPECT_EQ(e1[1], v1_first[1]);
    EXPECT_EQ(e2[0], v2_second[0]);
    EXPECT_EQ(e2[1], v2_second[1]);

    const uint8_t* const data_ptr_before_finalize = buffer.GetWriteBuffer().data();
    std::vector<uint8_t> final_buffer = buffer.FinalizeAndTakeBuffer();
    EXPECT_EQ(final_buffer.data(), data_ptr_before_finalize);  // Fixed-size finalize should move write_buffer_ directly.
    ASSERT_EQ(final_buffer.size(), 6u);
    EXPECT_EQ(final_buffer[0], v0_second[0]);
    EXPECT_EQ(final_buffer[1], v0_second[1]);
    EXPECT_EQ(final_buffer[2], v1_first[0]);
    EXPECT_EQ(final_buffer[3], v1_first[1]);
    EXPECT_EQ(final_buffer[4], v2_second[0]);
    EXPECT_EQ(final_buffer[5], v2_second[1]);
}

TEST(ByteBufferTest, SetElement_FixedSize_WrongPayloadSize_Throws) {
    ByteBufferTestProxy buffer(1u, 4u);
    std::vector<uint8_t> wrong = {0x01, 0x02};
    EXPECT_THROW((void)buffer.SetElement(0, tcb::span<const uint8_t>(wrong)), InvalidInputException);
}

TEST(ByteBufferTest, SetElement_OnReadOnlyBuffer_Throws) {
    std::vector<uint8_t> bytes = {0x10, 0x11, 0x20, 0x21};
    ByteBufferTestProxy buffer(tcb::span<const uint8_t>(bytes), 2);
    std::vector<uint8_t> replacement = {0xAA, 0xBB};
    EXPECT_THROW((void)buffer.SetElement(0, tcb::span<const uint8_t>(replacement)), InvalidInputException);
}

TEST(ByteBufferTest, Iterate_OnWriteBuffer_Throws) {
    ByteBufferTestProxy buffer(3u, 2u);
    EXPECT_THROW((void)buffer.begin(), InvalidInputException);
    EXPECT_THROW((void)buffer.end(), InvalidInputException);
}

TEST(ByteBufferTest, ConstructVariableSize_EmptyBuffer_InitializesEmptyState) {
    std::vector<uint8_t> bytes;
    ByteBufferTestProxy buffer{tcb::span<const uint8_t>(bytes)};
    ExpectCommonState(buffer, 0u, false, 0u);
    EXPECT_TRUE(buffer.GetOffsets().empty());
}

TEST(ByteBufferTest, ConstructVariableSize_TruncatedLengthPrefix_Throws) {
    std::vector<uint8_t> bytes = {0x01, 0x00, 0x00}; // only 3 bytes
    ByteBufferTestProxy buffer{tcb::span<const uint8_t>(bytes)};
    EXPECT_THROW((void)buffer.GetElement(0), InvalidInputException);
}

TEST(ByteBufferTest, ConstructVariableSize_TruncatedPayload_Throws) {
    // Declares payload length 5, but provides only 2 bytes.
    std::vector<uint8_t> bytes = {
        0x05, 0x00, 0x00, 0x00, 0xAA, 0xBB
    };
    ByteBufferTestProxy buffer{tcb::span<const uint8_t>(bytes)};
    EXPECT_THROW((void)buffer.GetElement(0), InvalidInputException);
}
