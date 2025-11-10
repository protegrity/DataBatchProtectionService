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

#include "enum_utils.h"
#include <iostream>
#include <gtest/gtest.h>
#include <set>
#include <algorithm>

using namespace dbps::enum_utils;
using namespace dbps::external;

// Test Type enum conversions
TEST(EnumUtils, TypeToStringConversion) {
    ASSERT_EQ("BOOLEAN", std::string(to_string(Type::BOOLEAN)));
    ASSERT_EQ("INT32", std::string(to_string(Type::INT32)));
    ASSERT_EQ("INT64", std::string(to_string(Type::INT64)));
    ASSERT_EQ("INT96", std::string(to_string(Type::INT96)));
    ASSERT_EQ("FLOAT", std::string(to_string(Type::FLOAT)));
    ASSERT_EQ("DOUBLE", std::string(to_string(Type::DOUBLE)));
    ASSERT_EQ("BYTE_ARRAY", std::string(to_string(Type::BYTE_ARRAY)));
    ASSERT_EQ("FIXED_LEN_BYTE_ARRAY", std::string(to_string(Type::FIXED_LEN_BYTE_ARRAY)));
    ASSERT_EQ("UNDEFINED", std::string(to_string(Type::UNDEFINED)));
}

TEST(EnumUtils, TypeFromStringConversion) {
    auto result = to_datatype_enum("BOOLEAN");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::BOOLEAN, result.value());
    
    result = to_datatype_enum("INT32");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::INT32, result.value());
    
    result = to_datatype_enum("INT64");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::INT64, result.value());
    
    result = to_datatype_enum("INT96");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::INT96, result.value());
    
    result = to_datatype_enum("FLOAT");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::FLOAT, result.value());
    
    result = to_datatype_enum("DOUBLE");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::DOUBLE, result.value());
    
    result = to_datatype_enum("BYTE_ARRAY");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::BYTE_ARRAY, result.value());
    
    result = to_datatype_enum("FIXED_LEN_BYTE_ARRAY");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::FIXED_LEN_BYTE_ARRAY, result.value());
    
    result = to_datatype_enum("UNDEFINED");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::UNDEFINED, result.value());
}

TEST(EnumUtils, TypeInvalidFromString) {
    auto result = to_datatype_enum("INVALID");
    ASSERT_FALSE(result.has_value());
    
    result = to_datatype_enum("boolean");  // lowercase
    ASSERT_FALSE(result.has_value());
    
    result = to_datatype_enum("BYTEARRAY");  // missing underscore
    ASSERT_FALSE(result.has_value());
    
    result = to_datatype_enum("");
    ASSERT_FALSE(result.has_value());
    
    result = to_datatype_enum("UNKNOWN");
    ASSERT_FALSE(result.has_value());
}

// Test CompressionCodec enum conversions
TEST(EnumUtils, CompressionCodecToStringConversion) {
    ASSERT_EQ("UNCOMPRESSED", std::string(to_string(CompressionCodec::UNCOMPRESSED)));
    ASSERT_EQ("SNAPPY", std::string(to_string(CompressionCodec::SNAPPY)));
    ASSERT_EQ("GZIP", std::string(to_string(CompressionCodec::GZIP)));
    ASSERT_EQ("BROTLI", std::string(to_string(CompressionCodec::BROTLI)));
    ASSERT_EQ("ZSTD", std::string(to_string(CompressionCodec::ZSTD)));
    ASSERT_EQ("LZ4", std::string(to_string(CompressionCodec::LZ4)));
    ASSERT_EQ("LZ4_FRAME", std::string(to_string(CompressionCodec::LZ4_FRAME)));
    ASSERT_EQ("LZO", std::string(to_string(CompressionCodec::LZO)));
    ASSERT_EQ("BZ2", std::string(to_string(CompressionCodec::BZ2)));
    ASSERT_EQ("LZ4_HADOOP", std::string(to_string(CompressionCodec::LZ4_HADOOP)));
}

TEST(EnumUtils, CompressionCodecFromStringConversion) {
    auto result = to_compression_enum("UNCOMPRESSED");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::UNCOMPRESSED, result.value());
    
    result = to_compression_enum("SNAPPY");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::SNAPPY, result.value());
    
    result = to_compression_enum("GZIP");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::GZIP, result.value());
    
    result = to_compression_enum("BROTLI");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::BROTLI, result.value());
    
    result = to_compression_enum("ZSTD");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::ZSTD, result.value());
    
    result = to_compression_enum("LZ4");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::LZ4, result.value());
    
    result = to_compression_enum("LZ4_FRAME");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::LZ4_FRAME, result.value());
    
    result = to_compression_enum("LZO");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::LZO, result.value());
    
    result = to_compression_enum("BZ2");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::BZ2, result.value());
    
    result = to_compression_enum("LZ4_HADOOP");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::LZ4_HADOOP, result.value());
}

TEST(EnumUtils, CompressionCodecInvalidFromString) {
    auto result = to_compression_enum("INVALID");
    ASSERT_FALSE(result.has_value());
    
    result = to_compression_enum("gzip");  // lowercase
    ASSERT_FALSE(result.has_value());
    
    result = to_compression_enum("LZ4RAW");  // missing underscore
    ASSERT_FALSE(result.has_value());
    
    result = to_compression_enum("");
    ASSERT_FALSE(result.has_value());
    
    result = to_compression_enum("NONE");  // common alternative
    ASSERT_FALSE(result.has_value());
}

// Test Format enum conversions
TEST(EnumUtils, FormatToStringConversion) {
    ASSERT_EQ("PLAIN", std::string(to_string(Format::PLAIN)));
    ASSERT_EQ("PLAIN_DICTIONARY", std::string(to_string(Format::PLAIN_DICTIONARY)));
    ASSERT_EQ("RLE", std::string(to_string(Format::RLE)));
    ASSERT_EQ("BIT_PACKED", std::string(to_string(Format::BIT_PACKED)));
    ASSERT_EQ("DELTA_BINARY_PACKED", std::string(to_string(Format::DELTA_BINARY_PACKED)));
    ASSERT_EQ("DELTA_LENGTH_BYTE_ARRAY", std::string(to_string(Format::DELTA_LENGTH_BYTE_ARRAY)));
    ASSERT_EQ("DELTA_BYTE_ARRAY", std::string(to_string(Format::DELTA_BYTE_ARRAY)));
    ASSERT_EQ("RLE_DICTIONARY", std::string(to_string(Format::RLE_DICTIONARY)));
    ASSERT_EQ("BYTE_STREAM_SPLIT", std::string(to_string(Format::BYTE_STREAM_SPLIT)));
    ASSERT_EQ("UNDEFINED", std::string(to_string(Format::UNDEFINED)));
    ASSERT_EQ("UNKNOWN", std::string(to_string(Format::UNKNOWN)));
}

TEST(EnumUtils, FormatFromStringConversion) {
    auto result = to_format_enum("PLAIN");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::PLAIN, result.value());
    
    result = to_format_enum("PLAIN_DICTIONARY");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::PLAIN_DICTIONARY, result.value());
    
    result = to_format_enum("RLE");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::RLE, result.value());
    
    result = to_format_enum("BIT_PACKED");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::BIT_PACKED, result.value());
    
    result = to_format_enum("DELTA_BINARY_PACKED");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::DELTA_BINARY_PACKED, result.value());
    
    result = to_format_enum("DELTA_LENGTH_BYTE_ARRAY");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::DELTA_LENGTH_BYTE_ARRAY, result.value());
    
    result = to_format_enum("DELTA_BYTE_ARRAY");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::DELTA_BYTE_ARRAY, result.value());
    
    result = to_format_enum("RLE_DICTIONARY");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::RLE_DICTIONARY, result.value());
    
    result = to_format_enum("BYTE_STREAM_SPLIT");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::BYTE_STREAM_SPLIT, result.value());
    
    result = to_format_enum("UNDEFINED");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::UNDEFINED, result.value());
    
    result = to_format_enum("UNKNOWN");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::UNKNOWN, result.value());
}

TEST(EnumUtils, FormatInvalidFromString) {
    auto result = to_format_enum("INVALID");
    ASSERT_FALSE(result.has_value());
    
    
    result = to_format_enum("RAWC_DATA");  // missing underscore
    ASSERT_FALSE(result.has_value());
    
    result = to_format_enum("");
    ASSERT_FALSE(result.has_value());
    
    result = to_format_enum("XML");  // common format
    ASSERT_FALSE(result.has_value());
}


// Test round-trip conversions
TEST(EnumUtils, RoundTripTypeConversion) {
    // Test all Type enum values
    Type::type types[] = {
        Type::BOOLEAN, Type::INT32, Type::INT64, Type::INT96,
        Type::FLOAT, Type::DOUBLE, Type::BYTE_ARRAY, Type::FIXED_LEN_BYTE_ARRAY, Type::UNDEFINED
    };
    
    for (auto type : types) {
        auto str = to_string(type);
        auto converted = to_datatype_enum(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(type, converted.value());
    }
}

TEST(EnumUtils, RoundTripCompressionCodecConversion) {
    // Test all CompressionCodec enum values
    CompressionCodec::type codecs[] = {
        CompressionCodec::UNCOMPRESSED, CompressionCodec::SNAPPY, CompressionCodec::GZIP,
        CompressionCodec::BROTLI, CompressionCodec::ZSTD, CompressionCodec::LZ4,
        CompressionCodec::LZ4_FRAME, CompressionCodec::LZO, CompressionCodec::BZ2,
        CompressionCodec::LZ4_HADOOP
    };
    
    for (auto codec : codecs) {
        auto str = to_string(codec);
        auto converted = to_compression_enum(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(codec, converted.value());
    }
}

TEST(EnumUtils, RoundTripFormatConversion) {
    // Test all Format enum values
    Format::type formats[] = {
        Format::PLAIN, Format::PLAIN_DICTIONARY, Format::RLE, Format::BIT_PACKED, Format::DELTA_BINARY_PACKED, Format::DELTA_LENGTH_BYTE_ARRAY, Format::DELTA_BYTE_ARRAY, Format::RLE_DICTIONARY, Format::BYTE_STREAM_SPLIT, Format::UNDEFINED, Format::UNKNOWN
    };
    
    for (auto format : formats) {
        auto str = to_string(format);
        auto converted = to_format_enum(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(format, converted.value());
    }
}


// Test edge cases
TEST(EnumUtils, EmptyStringHandling) {
    ASSERT_FALSE(to_datatype_enum("").has_value());
    ASSERT_FALSE(to_compression_enum("").has_value());
    ASSERT_FALSE(to_format_enum("").has_value());
}

TEST(EnumUtils, WhitespaceHandling) {
    ASSERT_FALSE(to_datatype_enum(" BYTE_ARRAY").has_value());
    ASSERT_FALSE(to_datatype_enum("BYTE_ARRAY ").has_value());
    ASSERT_FALSE(to_datatype_enum(" BYTE_ARRAY ").has_value());
    
    ASSERT_FALSE(to_compression_enum(" GZIP").has_value());
    ASSERT_FALSE(to_compression_enum("GZIP ").has_value());
    ASSERT_FALSE(to_compression_enum(" GZIP ").has_value());
}

TEST(EnumUtils, CaseSensitivity) {
    // Test that conversions are case-sensitive
    ASSERT_FALSE(to_datatype_enum("byte_array").has_value());
    ASSERT_FALSE(to_datatype_enum("Byte_Array").has_value());
    ASSERT_FALSE(to_datatype_enum("BYTE_array").has_value());
    
    ASSERT_FALSE(to_compression_enum("gzip").has_value());
    ASSERT_FALSE(to_compression_enum("Gzip").has_value());
    ASSERT_FALSE(to_compression_enum("GZIp").has_value());
}

TEST(EnumUtils, StringViewCompatibility) {
    // Test that string_view works correctly
    std::string_view type_str = "BYTE_ARRAY";
    auto result = to_datatype_enum(type_str);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::BYTE_ARRAY, result.value());
    
    std::string_view codec_str = "BZ2";
    auto codec_result = to_compression_enum(codec_str);
    ASSERT_TRUE(codec_result.has_value());
    ASSERT_EQ(CompressionCodec::BZ2, codec_result.value());
}

// Test runtime evaluation
TEST(EnumUtils, RuntimeEvaluation) {
    // Test runtime evaluation of the functions
    auto type_str = to_string(Type::BYTE_ARRAY);
    auto codec_str = to_string(CompressionCodec::BZ2);
    auto format_str = to_string(Format::RLE);
    // Verify the results
    ASSERT_EQ("BYTE_ARRAY", std::string(type_str));
    ASSERT_EQ("BZ2", std::string(codec_str));
    ASSERT_EQ("RLE", std::string(format_str));
}

// Protection tests: ensure enum_utils stays in sync with enum definitions
TEST(EnumUtils, TypeEnumCompleteness) {
    // Define all known Type enum values
    Type::type all_types[] = {
        Type::BOOLEAN, Type::INT32, Type::INT64, Type::INT96,
        Type::FLOAT, Type::DOUBLE, Type::BYTE_ARRAY, Type::FIXED_LEN_BYTE_ARRAY, Type::UNDEFINED
    };
    
    // Test that every enum value can be converted to string and back
    for (auto type : all_types) {
        auto str = to_string(type);
        ASSERT_TRUE(str != "UNKNOWN_ENUM");  // Should not return UNKNOWN_ENUM for valid enum
        
        auto converted = to_datatype_enum(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(type, converted.value());
    }
}

TEST(EnumUtils, CompressionCodecEnumCompleteness) {
    // Define all known CompressionCodec enum values
    CompressionCodec::type all_codecs[] = {
        CompressionCodec::UNCOMPRESSED, CompressionCodec::SNAPPY, CompressionCodec::GZIP,
        CompressionCodec::BROTLI, CompressionCodec::ZSTD, CompressionCodec::LZ4,
        CompressionCodec::LZ4_FRAME, CompressionCodec::LZO, CompressionCodec::BZ2,
        CompressionCodec::LZ4_HADOOP
    };
    
    // Test that every enum value can be converted to string and back
    for (auto codec : all_codecs) {
        auto str = to_string(codec);
        ASSERT_TRUE(str != "UNKNOWN_ENUM");  // Should not return UNKNOWN_ENUM for valid enum
        
        auto converted = to_compression_enum(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(codec, converted.value());
    }
}

TEST(EnumUtils, FormatEnumCompleteness) {
    // Define all known Format enum values
    Format::type all_formats[] = {
        Format::PLAIN, Format::PLAIN_DICTIONARY, Format::RLE, Format::BIT_PACKED, Format::DELTA_BINARY_PACKED, Format::DELTA_LENGTH_BYTE_ARRAY, Format::DELTA_BYTE_ARRAY, Format::RLE_DICTIONARY, Format::BYTE_STREAM_SPLIT, Format::UNDEFINED, Format::UNKNOWN
    };
    
    // Test that every enum value can be converted to string and back
    for (auto format : all_formats) {
        auto str = to_string(format);
        ASSERT_TRUE(str != "UNKNOWN_ENUM");  // Should not return UNKNOWN_ENUM for valid enum
        
        auto converted = to_format_enum(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(format, converted.value());
    }
}

TEST(EnumUtils, StringUniqueness) {
    // Test that all string representations are unique
    std::set<std::string> type_strings;
    std::set<std::string> codec_strings;
    std::set<std::string> format_strings;
    // Collect all Type strings
    Type::type all_types[] = {
        Type::BOOLEAN, Type::INT32, Type::INT64, Type::INT96,
        Type::FLOAT, Type::DOUBLE, Type::BYTE_ARRAY, Type::FIXED_LEN_BYTE_ARRAY, Type::UNDEFINED
    };
    for (auto type : all_types) {
        type_strings.insert(std::string(to_string(type)));
    }
    ASSERT_EQ(9, type_strings.size());  // All strings should be unique
    
    // Collect all CompressionCodec strings
    CompressionCodec::type all_codecs[] = {
        CompressionCodec::UNCOMPRESSED, CompressionCodec::SNAPPY, CompressionCodec::GZIP,
        CompressionCodec::BROTLI, CompressionCodec::ZSTD, CompressionCodec::LZ4,
        CompressionCodec::LZ4_FRAME, CompressionCodec::LZO, CompressionCodec::BZ2,
        CompressionCodec::LZ4_HADOOP
    };
    for (auto codec : all_codecs) {
        codec_strings.insert(std::string(to_string(codec)));
    }
    ASSERT_EQ(10, codec_strings.size());  // All strings should be unique
    
    // Collect all Format strings
    Format::type all_formats[] = {
        Format::PLAIN, Format::PLAIN_DICTIONARY, Format::RLE, Format::BIT_PACKED, Format::DELTA_BINARY_PACKED, Format::DELTA_LENGTH_BYTE_ARRAY, Format::DELTA_BYTE_ARRAY, Format::RLE_DICTIONARY, Format::BYTE_STREAM_SPLIT, Format::UNDEFINED, Format::UNKNOWN
    };
    for (auto format : all_formats) {
        format_strings.insert(std::string(to_string(format)));
    }
    ASSERT_EQ(11, format_strings.size());  // All strings should be unique
    
}

TEST(EnumUtils, CrossEnumStringCollision) {
    // Test that strings from different enums are collected correctly
    // Note: Some enums may intentionally share the same string representation
    std::set<std::string> all_strings;
    
    // Collect all strings from all enums
    Type::type all_types[] = {
        Type::BOOLEAN, Type::INT32, Type::INT64, Type::INT96,
        Type::FLOAT, Type::DOUBLE, Type::BYTE_ARRAY, Type::FIXED_LEN_BYTE_ARRAY, Type::UNDEFINED
    };
    for (auto type : all_types) {
        all_strings.insert(std::string(to_string(type)));
    }
    
    CompressionCodec::type all_codecs[] = {
        CompressionCodec::UNCOMPRESSED, CompressionCodec::SNAPPY, CompressionCodec::GZIP,
        CompressionCodec::BROTLI, CompressionCodec::ZSTD, CompressionCodec::LZ4,
        CompressionCodec::LZ4_FRAME, CompressionCodec::LZO, CompressionCodec::BZ2,
        CompressionCodec::LZ4_HADOOP
    };
    for (auto codec : all_codecs) {
        all_strings.insert(std::string(to_string(codec)));
    }
    
    Format::type all_formats[] = {
        Format::PLAIN, Format::PLAIN_DICTIONARY, Format::RLE, Format::BIT_PACKED, Format::DELTA_BINARY_PACKED, Format::DELTA_LENGTH_BYTE_ARRAY, Format::DELTA_BYTE_ARRAY, Format::RLE_DICTIONARY, Format::BYTE_STREAM_SPLIT, Format::UNDEFINED, Format::UNKNOWN
    };
    for (auto format : all_formats) {
        all_strings.insert(std::string(to_string(format)));
    }
    
    // Verify two equally named enums are handled correctly.
    ASSERT_EQ("UNDEFINED", std::string(to_string(Type::UNDEFINED)));
    ASSERT_EQ("UNDEFINED", std::string(to_string(Format::UNDEFINED)));
    
    // Total should be 9 + 10 + 11 = 30 unique strings, but we have 1 collision
    // (Type::UNDEFINED and Format::UNDEFINED both map to "UNDEFINED")
    // So we expect 29 unique strings
    ASSERT_EQ(29, all_strings.size());
}
