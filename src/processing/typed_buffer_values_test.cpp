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

#include "typed_buffer_values.h"
#include "typed_buffer_testing_codecs.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "bytes_utils.h"
#include "exceptions.h"

using namespace dbps::processing; 
using dbps::processing::testing::StringFixedSizedCodec;
using dbps::processing::testing::TypedBufferStringFixedSized;
using dbps::processing::testing::TypedBufferStringVariableSized;

// =============================================================================
// INT32
// =============================================================================

TEST(TypedBufferValuesTest, Int32_ReadBack) {
    std::vector<uint8_t> bytes;
    append_i32_le(bytes, 42);
    append_i32_le(bytes, -1);
    append_i32_le(bytes, 0);
    append_i32_le(bytes, 2147483647);

    TypedBufferI32 buffer{tcb::span<const uint8_t>(bytes), 4u};

    EXPECT_EQ(buffer.GetElement(0), 42);
    EXPECT_EQ(buffer.GetElement(1), -1);
    EXPECT_EQ(buffer.GetElement(2), 0);
    EXPECT_EQ(buffer.GetElement(3), 2147483647);
}

TEST(TypedBufferValuesTest, Int32_WriteAndReadBack) {
    TypedBufferI32 buffer(3u);

    buffer.SetElement(0, 100);
    buffer.SetElement(1, -999);
    buffer.SetElement(2, 0);

    EXPECT_EQ(buffer.GetElement(0), 100);
    EXPECT_EQ(buffer.GetElement(1), -999);
    EXPECT_EQ(buffer.GetElement(2), 0);
}

TEST(TypedBufferValuesTest, Int32_WriteRoundTrip) {
    TypedBufferI32 writer(3u);
    writer.SetElement(0, 10);
    writer.SetElement(1, 20);
    writer.SetElement(2, 30);

    std::vector<uint8_t> finalized = writer.FinalizeAndTakeBuffer();
    TypedBufferI32 reader{tcb::span<const uint8_t>(finalized), 3u};

    EXPECT_EQ(reader.GetElement(0), 10);
    EXPECT_EQ(reader.GetElement(1), 20);
    EXPECT_EQ(reader.GetElement(2), 30);
}

TEST(TypedBufferValuesTest, Int32_Iterate) {
    std::vector<uint8_t> bytes;
    append_i32_le(bytes, 5);
    append_i32_le(bytes, 10);
    append_i32_le(bytes, 15);

    TypedBufferI32 buffer{tcb::span<const uint8_t>(bytes), 3u};

    std::vector<int32_t> collected;
    for (size_t i = 0; i < buffer.GetNumElements(); ++i) {
        const auto value = buffer.GetElement(i);
        collected.push_back(value);
    }

    ASSERT_EQ(collected.size(), 3u);
    EXPECT_EQ(collected[0], 5);
    EXPECT_EQ(collected[1], 10);
    EXPECT_EQ(collected[2], 15);
}

TEST(TypedBufferValuesTest, Int32_OutOfOrderWrite_RoundTrip) {
    TypedBufferI32 writer(4u);
    writer.SetElement(3, 40);
    writer.SetElement(1, 20);

    EXPECT_EQ(writer.GetElement(3), 40);
    EXPECT_EQ(writer.GetElement(1), 20);

    writer.SetElement(0, 10);
    writer.SetElement(2, 30);

    std::vector<uint8_t> finalized = writer.FinalizeAndTakeBuffer();
    TypedBufferI32 reader{tcb::span<const uint8_t>(finalized), 4u};

    EXPECT_EQ(reader.GetElement(0), 10);
    EXPECT_EQ(reader.GetElement(1), 20);
    EXPECT_EQ(reader.GetElement(2), 30);
    EXPECT_EQ(reader.GetElement(3), 40);
}

TEST(TypedBufferValuesTest, Int32_OverwriteThenRoundTrip) {
    TypedBufferI32 writer(2u);
    writer.SetElement(0, 111);
    writer.SetElement(1, 222);

    EXPECT_EQ(writer.GetElement(0), 111);

    writer.SetElement(0, 999);
    EXPECT_EQ(writer.GetElement(0), 999);
    EXPECT_EQ(writer.GetElement(1), 222);

    std::vector<uint8_t> finalized = writer.FinalizeAndTakeBuffer();
    TypedBufferI32 reader{tcb::span<const uint8_t>(finalized), 2u};

    EXPECT_EQ(reader.GetElement(0), 999);
    EXPECT_EQ(reader.GetElement(1), 222);
}

// =============================================================================
// INT96
// =============================================================================

namespace {
void AppendInt96LE(std::vector<uint8_t>& out, const Int96& v) {
    append_i32_le(out, v.lo);
    append_i32_le(out, v.mid);
    append_i32_le(out, v.hi);
}

void ExpectInt96Eq(const Int96& actual, const Int96& expected) {
    EXPECT_EQ(actual.lo, expected.lo);
    EXPECT_EQ(actual.mid, expected.mid);
    EXPECT_EQ(actual.hi, expected.hi);
}
} // namespace

TEST(TypedBufferValuesTest, Int96_ReadBack) {
    const Int96 a{1, 2, 3};
    const Int96 b{-1, 0, 2147483647};
    const Int96 c{0, 0, 0};

    std::vector<uint8_t> bytes;
    AppendInt96LE(bytes, a);
    AppendInt96LE(bytes, b);
    AppendInt96LE(bytes, c);

    TypedBufferInt96 buffer{tcb::span<const uint8_t>(bytes), 3u};

    ExpectInt96Eq(buffer.GetElement(0), a);
    ExpectInt96Eq(buffer.GetElement(1), b);
    ExpectInt96Eq(buffer.GetElement(2), c);
}

TEST(TypedBufferValuesTest, Int96_WriteRoundTrip) {
    const Int96 a{10, 20, 30};
    const Int96 b{-100, -200, -300};

    TypedBufferInt96 writer(2u);
    writer.SetElement(0, a);
    writer.SetElement(1, b);

    std::vector<uint8_t> finalized = writer.FinalizeAndTakeBuffer();
    TypedBufferInt96 reader{tcb::span<const uint8_t>(finalized), 2u};

    ExpectInt96Eq(reader.GetElement(0), a);
    ExpectInt96Eq(reader.GetElement(1), b);
}

TEST(TypedBufferValuesTest, Int96_Iterate) {
    const Int96 a{100, 200, 300};
    const Int96 b{400, 500, 600};

    std::vector<uint8_t> bytes;
    AppendInt96LE(bytes, a);
    AppendInt96LE(bytes, b);

    TypedBufferInt96 buffer{tcb::span<const uint8_t>(bytes), 2u};

    std::vector<Int96> collected;
    for (size_t i = 0; i < buffer.GetNumElements(); ++i) {
        const auto value = buffer.GetElement(i);
        collected.push_back(value);
    }

    ASSERT_EQ(collected.size(), 2u);
    ExpectInt96Eq(collected[0], a);
    ExpectInt96Eq(collected[1], b);
}

TEST(TypedBufferValuesTest, Int96_OutOfOrderWrite_RoundTrip) {
    const Int96 a{1, 2, 3};
    const Int96 b{4, 5, 6};
    const Int96 c{7, 8, 9};

    TypedBufferInt96 writer(3u);
    writer.SetElement(2, c);
    writer.SetElement(0, a);
    writer.SetElement(1, b);

    std::vector<uint8_t> finalized = writer.FinalizeAndTakeBuffer();
    TypedBufferInt96 reader{tcb::span<const uint8_t>(finalized), 3u};

    ExpectInt96Eq(reader.GetElement(0), a);
    ExpectInt96Eq(reader.GetElement(1), b);
    ExpectInt96Eq(reader.GetElement(2), c);
}

// =============================================================================
// FLOAT
// =============================================================================

TEST(TypedBufferValuesTest, Float_ReadBack) {
    std::vector<uint8_t> bytes;
    append_f32_le(bytes, 3.14f);
    append_f32_le(bytes, -0.0f);
    append_f32_le(bytes, 1.0e10f);

    TypedBufferFloat buffer{tcb::span<const uint8_t>(bytes), 3u};

    EXPECT_FLOAT_EQ(buffer.GetElement(0), 3.14f);
    EXPECT_FLOAT_EQ(buffer.GetElement(1), -0.0f);
    EXPECT_FLOAT_EQ(buffer.GetElement(2), 1.0e10f);
}

TEST(TypedBufferValuesTest, Float_WriteRoundTrip) {
    TypedBufferFloat writer(3u);
    writer.SetElement(0, 1.5f);
    writer.SetElement(1, -2.25f);
    writer.SetElement(2, 0.0f);

    std::vector<uint8_t> finalized = writer.FinalizeAndTakeBuffer();
    TypedBufferFloat reader{tcb::span<const uint8_t>(finalized), 3u};

    EXPECT_FLOAT_EQ(reader.GetElement(0), 1.5f);
    EXPECT_FLOAT_EQ(reader.GetElement(1), -2.25f);
    EXPECT_FLOAT_EQ(reader.GetElement(2), 0.0f);
}

TEST(TypedBufferValuesTest, Float_Iterate) {
    std::vector<uint8_t> bytes;
    append_f32_le(bytes, 1.0f);
    append_f32_le(bytes, 2.0f);
    append_f32_le(bytes, 3.0f);

    TypedBufferFloat buffer{tcb::span<const uint8_t>(bytes), 3u};

    std::vector<float> collected;
    for (size_t i = 0; i < buffer.GetNumElements(); ++i) {
        const auto value = buffer.GetElement(i);
        collected.push_back(value);
    }

    ASSERT_EQ(collected.size(), 3u);
    EXPECT_FLOAT_EQ(collected[0], 1.0f);
    EXPECT_FLOAT_EQ(collected[1], 2.0f);
    EXPECT_FLOAT_EQ(collected[2], 3.0f);
}

TEST(TypedBufferValuesTest, Float_OutOfOrderWrite_InterleavedReads) {
    TypedBufferFloat writer(3u);
    writer.SetElement(2, 30.0f);
    EXPECT_FLOAT_EQ(writer.GetElement(2), 30.0f);

    writer.SetElement(0, 10.0f);
    EXPECT_FLOAT_EQ(writer.GetElement(0), 10.0f);
    EXPECT_FLOAT_EQ(writer.GetElement(2), 30.0f);

    writer.SetElement(1, 20.0f);

    writer.SetElement(2, 99.0f);
    EXPECT_FLOAT_EQ(writer.GetElement(2), 99.0f);

    std::vector<uint8_t> finalized = writer.FinalizeAndTakeBuffer();
    TypedBufferFloat reader{tcb::span<const uint8_t>(finalized), 3u};

    EXPECT_FLOAT_EQ(reader.GetElement(0), 10.0f);
    EXPECT_FLOAT_EQ(reader.GetElement(1), 20.0f);
    EXPECT_FLOAT_EQ(reader.GetElement(2), 99.0f);
}

// =============================================================================
// STRING FIXED-SIZED
// =============================================================================

TEST(TypedBufferValuesTest, StringFixedSized_ReadBack) {
    // Three 4-byte fixed-length strings: "ABCD", "EFGH", "1234"
    std::vector<uint8_t> bytes = {
        'A', 'B', 'C', 'D',
        'E', 'F', 'G', 'H',
        '1', '2', '3', '4'
    };

    TypedBufferStringFixedSized buffer(
        tcb::span<const uint8_t>(bytes), 3u, 0u, StringFixedSizedCodec{4});

    EXPECT_EQ(buffer.GetElement(0), "ABCD");
    EXPECT_EQ(buffer.GetElement(1), "EFGH");
    EXPECT_EQ(buffer.GetElement(2), "1234");
}

TEST(TypedBufferValuesTest, StringFixedSized_WriteRoundTrip) {
    TypedBufferStringFixedSized writer(3u, 0, StringFixedSizedCodec{4});

    writer.SetElement(0, std::string_view("AAAA"));
    writer.SetElement(1, std::string_view("BBBB"));
    writer.SetElement(2, std::string_view("CCCC"));

    std::vector<uint8_t> finalized = writer.FinalizeAndTakeBuffer();
    TypedBufferStringFixedSized reader(
        tcb::span<const uint8_t>(finalized), 3u, 0u, StringFixedSizedCodec{4});

    EXPECT_EQ(reader.GetElement(0), "AAAA");
    EXPECT_EQ(reader.GetElement(1), "BBBB");
    EXPECT_EQ(reader.GetElement(2), "CCCC");
}

TEST(TypedBufferValuesTest, StringFixedSized_Iterate) {
    std::vector<uint8_t> bytes = {
        'H', 'i', '!', ' ',
        'B', 'y', 'e', '!'
    };

    TypedBufferStringFixedSized buffer(
        tcb::span<const uint8_t>(bytes), 2u, 0u, StringFixedSizedCodec{4});

    std::vector<std::string> collected;
    for (size_t i = 0; i < buffer.GetNumElements(); ++i) {
        const auto value = buffer.GetElement(i);
        collected.emplace_back(value);
    }

    ASSERT_EQ(collected.size(), 2u);
    EXPECT_EQ(collected[0], "Hi! ");
    EXPECT_EQ(collected[1], "Bye!");
}

TEST(TypedBufferValuesTest, StringFixedSized_OutOfOrderWrite_RoundTrip) {
    TypedBufferStringFixedSized writer(3u, 0, StringFixedSizedCodec{3});

    writer.SetElement(2, std::string_view("CCC"));
    writer.SetElement(0, std::string_view("AAA"));

    EXPECT_EQ(writer.GetElement(2), "CCC");
    EXPECT_EQ(writer.GetElement(0), "AAA");

    writer.SetElement(1, std::string_view("BBB"));

    writer.SetElement(0, std::string_view("ZZZ"));

    std::vector<uint8_t> finalized = writer.FinalizeAndTakeBuffer();
    TypedBufferStringFixedSized reader(
        tcb::span<const uint8_t>(finalized), 3u, 0u, StringFixedSizedCodec{3});

    EXPECT_EQ(reader.GetElement(0), "ZZZ");
    EXPECT_EQ(reader.GetElement(1), "BBB");
    EXPECT_EQ(reader.GetElement(2), "CCC");
}

TEST(TypedBufferValuesTest, StringFixedSized_ZeroSize_Throws) {
    EXPECT_THROW(StringFixedSizedCodec{0}, InvalidInputException);
}

// =============================================================================
// STRING VARIABLE-SIZED
// =============================================================================

TEST(TypedBufferValuesTest, StringVariableSized_ReadBack) {
    // [len=5]["Hello"][len=6]["World!"]
    std::vector<uint8_t> bytes;
    append_u32_le(bytes, 5u);
    bytes.insert(bytes.end(), {'H', 'e', 'l', 'l', 'o'});
    append_u32_le(bytes, 6u);
    bytes.insert(bytes.end(), {'W', 'o', 'r', 'l', 'd', '!'});

    TypedBufferStringVariableSized buffer{tcb::span<const uint8_t>(bytes), 2u};

    EXPECT_EQ(buffer.GetElement(0), "Hello");
    EXPECT_EQ(buffer.GetElement(1), "World!");
}

TEST(TypedBufferValuesTest, StringVariableSized_WriteRoundTrip) {
    TypedBufferStringVariableSized writer(3u, 64u, true);

    writer.SetElement(0, std::string_view("short"));
    writer.SetElement(1, std::string_view("a longer string value"));
    writer.SetElement(2, std::string_view("x"));

    std::vector<uint8_t> finalized = writer.FinalizeAndTakeBuffer();
    TypedBufferStringVariableSized reader{tcb::span<const uint8_t>(finalized), 3u};

    EXPECT_EQ(reader.GetElement(0), "short");
    EXPECT_EQ(reader.GetElement(1), "a longer string value");
    EXPECT_EQ(reader.GetElement(2), "x");
}

TEST(TypedBufferValuesTest, StringVariableSized_Iterate) {
    std::vector<uint8_t> bytes;
    append_u32_le(bytes, 3u);
    bytes.insert(bytes.end(), {'f', 'o', 'o'});
    append_u32_le(bytes, 6u);
    bytes.insert(bytes.end(), {'b', 'a', 'r', 'b', 'a', 'z'});

    TypedBufferStringVariableSized buffer{tcb::span<const uint8_t>(bytes), 2u};

    std::vector<std::string> collected;
    for (size_t i = 0; i < buffer.GetNumElements(); ++i) {
        const auto value = buffer.GetElement(i);
        collected.emplace_back(value);
    }

    ASSERT_EQ(collected.size(), 2u);
    EXPECT_EQ(collected[0], "foo");
    EXPECT_EQ(collected[1], "barbaz");
}

TEST(TypedBufferValuesTest, StringVariableSized_OutOfOrderWrite_RoundTrip) {
    TypedBufferStringVariableSized writer(3u, 64u, true);

    writer.SetElement(2, std::string_view("third"));
    writer.SetElement(0, std::string_view("first-value"));

    EXPECT_EQ(writer.GetElement(2), "third");
    EXPECT_EQ(writer.GetElement(0), "first-value");

    writer.SetElement(1, std::string_view("second"));

    writer.SetElement(0, std::string_view("replaced"));
    EXPECT_EQ(writer.GetElement(0), "replaced");

    std::vector<uint8_t> finalized = writer.FinalizeAndTakeBuffer();
    TypedBufferStringVariableSized reader{tcb::span<const uint8_t>(finalized), 3u};

    EXPECT_EQ(reader.GetElement(0), "replaced");
    EXPECT_EQ(reader.GetElement(1), "second");
    EXPECT_EQ(reader.GetElement(2), "third");
}

TEST(TypedBufferValuesTest, StringVariableSized_EmptyStringsMixedWithNonEmpty) {
    TypedBufferStringVariableSized writer(8u, 128u, true);

    writer.SetElement(7, std::string_view("charlie"));
    writer.SetElement(2, std::string_view("alpha"));
    writer.SetElement(5, std::string_view(""));
    writer.SetElement(0, std::string_view(""));
    writer.SetElement(6, std::string_view("bravo"));
    writer.SetElement(3, std::string_view(""));
    writer.SetElement(1, std::string_view(""));
    writer.SetElement(4, std::string_view(""));

    std::vector<uint8_t> finalized = writer.FinalizeAndTakeBuffer();
    TypedBufferStringVariableSized reader{tcb::span<const uint8_t>(finalized), 8u};

    EXPECT_EQ(reader.GetElement(0), "");
    EXPECT_EQ(reader.GetElement(0).size(), 0u);
    EXPECT_EQ(reader.GetElement(1), "");
    EXPECT_EQ(reader.GetElement(1).size(), 0u);
    EXPECT_EQ(reader.GetElement(2), "alpha");
    EXPECT_EQ(reader.GetElement(3), "");
    EXPECT_EQ(reader.GetElement(3).size(), 0u);
    EXPECT_EQ(reader.GetElement(4), "");
    EXPECT_EQ(reader.GetElement(4).size(), 0u);
    EXPECT_EQ(reader.GetElement(5), "");
    EXPECT_EQ(reader.GetElement(5).size(), 0u);
    EXPECT_EQ(reader.GetElement(6), "bravo");
    EXPECT_EQ(reader.GetElement(7), "charlie");

    size_t element_count = 0;
    std::vector<std::string> collected;
    for (size_t i = 0; i < reader.GetNumElements(); ++i) {
        const auto value = reader.GetElement(i);
        collected.emplace_back(value);
        ++element_count;
    }

    ASSERT_EQ(element_count, 8u);
    EXPECT_EQ(collected[0], "");
    EXPECT_EQ(collected[1], "");
    EXPECT_EQ(collected[2], "alpha");
    EXPECT_EQ(collected[3], "");
    EXPECT_EQ(collected[4], "");
    EXPECT_EQ(collected[5], "");
    EXPECT_EQ(collected[6], "bravo");
    EXPECT_EQ(collected[7], "charlie");
}

TEST(TypedBufferValuesTest, StringVariableSized_UTF8_ReadBack) {
    // Variable-sized strings with UTF-8 content
    std::vector<uint8_t> bytes;
    
    // "Привет" (Russian, 12 bytes)
    std::string russian = "Привет";
    append_u32_le(bytes, static_cast<uint32_t>(russian.size()));
    bytes.insert(bytes.end(), russian.begin(), russian.end());
    
    // "مرحبا" (Arabic, 10 bytes)
    std::string arabic = "مرحبا";
    append_u32_le(bytes, static_cast<uint32_t>(arabic.size()));
    bytes.insert(bytes.end(), arabic.begin(), arabic.end());
    
    // "🎉🎊🎈" (Emojis, 12 bytes)
    std::string emojis = "🎉🎊🎈";
    append_u32_le(bytes, static_cast<uint32_t>(emojis.size()));
    bytes.insert(bytes.end(), emojis.begin(), emojis.end());

    TypedBufferStringVariableSized buffer{tcb::span<const uint8_t>(bytes), 3u};

    EXPECT_EQ(buffer.GetElement(0), "Привет");
    EXPECT_EQ(buffer.GetElement(1), "مرحبا");
    EXPECT_EQ(buffer.GetElement(2), "🎉🎊🎈");
}

TEST(TypedBufferValuesTest, StringVariableSized_UTF8_WriteRoundTrip) {
    TypedBufferStringVariableSized writer(4u, 256u, true);

    writer.SetElement(0, std::string_view("Héllo Wörld"));
    writer.SetElement(1, std::string_view("中文测试"));
    writer.SetElement(2, std::string_view("Emoji: 🚀🌟💻"));
    writer.SetElement(3, std::string_view("Ελληνικά"));

    std::vector<uint8_t> finalized = writer.FinalizeAndTakeBuffer();
    TypedBufferStringVariableSized reader{tcb::span<const uint8_t>(finalized), 4u};

    EXPECT_EQ(reader.GetElement(0), "Héllo Wörld");
    EXPECT_EQ(reader.GetElement(1), "中文测试");
    EXPECT_EQ(reader.GetElement(2), "Emoji: 🚀🌟💻");
    EXPECT_EQ(reader.GetElement(3), "Ελληνικά");
}

// =============================================================================
// TypedValuesBufferToString
// =============================================================================

TEST(TypedBufferValuesTest, TypedValuesBufferToString_BasicUsage) {
    // --- INT32: construct from raw bytes (creates a read buffer) ---
    std::vector<uint8_t> i32_bytes;
    append_i32_le(i32_bytes, 42);
    append_i32_le(i32_bytes, -1);
    append_i32_le(i32_bytes, 100);

    TypedValuesBuffer i32_variant = TypedBufferI32{tcb::span<const uint8_t>(i32_bytes), 3u};
    std::string i32_str = PrintableTypedValuesBuffer(i32_variant);

    EXPECT_NE(i32_str.find("INT32"), std::string::npos);
    EXPECT_NE(i32_str.find("3 elements"), std::string::npos);
    EXPECT_NE(i32_str.find("42"), std::string::npos);
    EXPECT_NE(i32_str.find("-1"), std::string::npos);
    EXPECT_NE(i32_str.find("100"), std::string::npos);

    // --- FLOAT: construct from raw bytes ---
    std::vector<uint8_t> float_bytes;
    append_f32_le(float_bytes, 3.14f);
    append_f32_le(float_bytes, -0.5f);

    TypedValuesBuffer float_variant = TypedBufferFloat{tcb::span<const uint8_t>(float_bytes), 2u};
    std::string float_str = PrintableTypedValuesBuffer(float_variant);

    EXPECT_NE(float_str.find("FLOAT"), std::string::npos);
    EXPECT_NE(float_str.find("2 elements"), std::string::npos);

    // --- Variable BYTE_ARRAY: write, finalize, then read ---
    const uint8_t blob1[] = {0xDE, 0xAD};
    const uint8_t blob2[] = {0xBE, 0xEF, 0xCA, 0xFE};

    TypedBufferRawBytesVariableSized writer(2u, 64u, true);
    writer.SetElement(0, tcb::span<const uint8_t>(blob1));
    writer.SetElement(1, tcb::span<const uint8_t>(blob2));

    std::vector<uint8_t> raw_finalized = writer.FinalizeAndTakeBuffer();
    TypedValuesBuffer raw_variant =
        TypedBufferRawBytesVariableSized{tcb::span<const uint8_t>(raw_finalized), 2u};
    std::string raw_str = PrintableTypedValuesBuffer(raw_variant);

    EXPECT_NE(raw_str.find("raw bytes (variable-length)"), std::string::npos);
    EXPECT_NE(raw_str.find("2 elements"), std::string::npos);
    EXPECT_NE(raw_str.find("2 bytes"), std::string::npos);
    EXPECT_NE(raw_str.find("4 bytes"), std::string::npos);
}
