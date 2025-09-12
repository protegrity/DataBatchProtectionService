#include "enum_utils.h"
#include <iostream>
#include <cassert>
#include <set>
#include <algorithm>

// Simple test framework
#define TEST(name) void test_##name()
#define ASSERT_EQ(expected, actual) \
    if ((expected) != (actual)) { \
        std::cerr << "FAILED: " << __FUNCTION__ << " - " << #expected << " != " << #actual << std::endl; \
        std::cerr << "Expected: " << (expected) << ", Got: " << (actual) << std::endl; \
        exit(1); \
    }
#define ASSERT_TRUE(condition) \
    if (!(condition)) { \
        std::cerr << "FAILED: " << __FUNCTION__ << " - " << #condition << " is false" << std::endl; \
        exit(1); \
    }
#define ASSERT_FALSE(condition) \
    if ((condition)) { \
        std::cerr << "FAILED: " << __FUNCTION__ << " - " << #condition << " is true" << std::endl; \
        exit(1); \
    }

using namespace dbps::enum_utils;
using namespace dbps::external;

// Test Type enum conversions
TEST(TypeToStringConversion) {
    ASSERT_EQ("BOOLEAN", std::string(to_string(Type::BOOLEAN)));
    ASSERT_EQ("INT32", std::string(to_string(Type::INT32)));
    ASSERT_EQ("INT64", std::string(to_string(Type::INT64)));
    ASSERT_EQ("INT96", std::string(to_string(Type::INT96)));
    ASSERT_EQ("FLOAT", std::string(to_string(Type::FLOAT)));
    ASSERT_EQ("DOUBLE", std::string(to_string(Type::DOUBLE)));
    ASSERT_EQ("BYTE_ARRAY", std::string(to_string(Type::BYTE_ARRAY)));
    ASSERT_EQ("FIXED_LEN_BYTE_ARRAY", std::string(to_string(Type::FIXED_LEN_BYTE_ARRAY)));
}

TEST(TypeFromStringConversion) {
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
}

TEST(TypeInvalidFromString) {
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
TEST(CompressionCodecToStringConversion) {
    ASSERT_EQ("UNCOMPRESSED", std::string(to_string(CompressionCodec::UNCOMPRESSED)));
    ASSERT_EQ("SNAPPY", std::string(to_string(CompressionCodec::SNAPPY)));
    ASSERT_EQ("GZIP", std::string(to_string(CompressionCodec::GZIP)));
    ASSERT_EQ("LZO", std::string(to_string(CompressionCodec::LZO)));
    ASSERT_EQ("BROTLI", std::string(to_string(CompressionCodec::BROTLI)));
    ASSERT_EQ("LZ4", std::string(to_string(CompressionCodec::LZ4)));
    ASSERT_EQ("ZSTD", std::string(to_string(CompressionCodec::ZSTD)));
    ASSERT_EQ("LZ4_RAW", std::string(to_string(CompressionCodec::LZ4_RAW)));
}

TEST(CompressionCodecFromStringConversion) {
    auto result = to_compression_enum("UNCOMPRESSED");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::UNCOMPRESSED, result.value());
    
    result = to_compression_enum("SNAPPY");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::SNAPPY, result.value());
    
    result = to_compression_enum("GZIP");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::GZIP, result.value());
    
    result = to_compression_enum("LZO");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::LZO, result.value());
    
    result = to_compression_enum("BROTLI");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::BROTLI, result.value());
    
    result = to_compression_enum("LZ4");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::LZ4, result.value());
    
    result = to_compression_enum("ZSTD");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::ZSTD, result.value());
    
    result = to_compression_enum("LZ4_RAW");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::LZ4_RAW, result.value());
}

TEST(CompressionCodecInvalidFromString) {
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
TEST(FormatToStringConversion) {
    ASSERT_EQ("UNDEFINED", std::string(to_string(Format::UNDEFINED)));
    ASSERT_EQ("PLAIN", std::string(to_string(Format::PLAIN)));
}

TEST(FormatFromStringConversion) {
    auto result = to_format_enum("UNDEFINED");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::UNDEFINED, result.value());
    
    result = to_format_enum("PLAIN");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::PLAIN, result.value());
}

TEST(FormatInvalidFromString) {
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
TEST(RoundTripTypeConversion) {
    // Test all Type enum values
    Type::type types[] = {
        Type::BOOLEAN, Type::INT32, Type::INT64, Type::INT96,
        Type::FLOAT, Type::DOUBLE, Type::BYTE_ARRAY, Type::FIXED_LEN_BYTE_ARRAY
    };
    
    for (auto type : types) {
        auto str = to_string(type);
        auto converted = to_datatype_enum(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(type, converted.value());
    }
}

TEST(RoundTripCompressionCodecConversion) {
    // Test all CompressionCodec enum values
    CompressionCodec::type codecs[] = {
        CompressionCodec::UNCOMPRESSED, CompressionCodec::SNAPPY, CompressionCodec::GZIP,
        CompressionCodec::LZO, CompressionCodec::BROTLI, CompressionCodec::LZ4,
        CompressionCodec::ZSTD, CompressionCodec::LZ4_RAW
    };
    
    for (auto codec : codecs) {
        auto str = to_string(codec);
        auto converted = to_compression_enum(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(codec, converted.value());
    }
}

TEST(RoundTripFormatConversion) {
    // Test all Format enum values
    Format::type formats[] = {
        Format::UNDEFINED, Format::PLAIN
    };
    
    for (auto format : formats) {
        auto str = to_string(format);
        auto converted = to_format_enum(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(format, converted.value());
    }
}


// Test edge cases
TEST(EmptyStringHandling) {
    ASSERT_FALSE(to_datatype_enum("").has_value());
    ASSERT_FALSE(to_compression_enum("").has_value());
    ASSERT_FALSE(to_format_enum("").has_value());
}

TEST(WhitespaceHandling) {
    ASSERT_FALSE(to_datatype_enum(" BYTE_ARRAY").has_value());
    ASSERT_FALSE(to_datatype_enum("BYTE_ARRAY ").has_value());
    ASSERT_FALSE(to_datatype_enum(" BYTE_ARRAY ").has_value());
    
    ASSERT_FALSE(to_compression_enum(" GZIP").has_value());
    ASSERT_FALSE(to_compression_enum("GZIP ").has_value());
    ASSERT_FALSE(to_compression_enum(" GZIP ").has_value());
}

TEST(CaseSensitivity) {
    // Test that conversions are case-sensitive
    ASSERT_FALSE(to_datatype_enum("byte_array").has_value());
    ASSERT_FALSE(to_datatype_enum("Byte_Array").has_value());
    ASSERT_FALSE(to_datatype_enum("BYTE_array").has_value());
    
    ASSERT_FALSE(to_compression_enum("gzip").has_value());
    ASSERT_FALSE(to_compression_enum("Gzip").has_value());
    ASSERT_FALSE(to_compression_enum("GZIp").has_value());
}

TEST(StringViewCompatibility) {
    // Test that string_view works correctly
    std::string_view type_str = "BYTE_ARRAY";
    auto result = to_datatype_enum(type_str);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::BYTE_ARRAY, result.value());
    
    std::string_view codec_str = "GZIP";
    auto codec_result = to_compression_enum(codec_str);
    ASSERT_TRUE(codec_result.has_value());
    ASSERT_EQ(CompressionCodec::GZIP, codec_result.value());
}

// Test runtime evaluation
TEST(RuntimeEvaluation) {
    // Test runtime evaluation of the functions
    auto type_str = to_string(Type::BYTE_ARRAY);
    auto codec_str = to_string(CompressionCodec::GZIP);
    auto format_str = to_string(Format::UNDEFINED);
    // Verify the results
    ASSERT_EQ("BYTE_ARRAY", std::string(type_str));
    ASSERT_EQ("GZIP", std::string(codec_str));
    ASSERT_EQ("UNDEFINED", std::string(format_str));
}

// Protection tests: ensure enum_utils stays in sync with enum definitions
TEST(TypeEnumCompleteness) {
    // Define all known Type enum values
    Type::type all_types[] = {
        Type::BOOLEAN, Type::INT32, Type::INT64, Type::INT96,
        Type::FLOAT, Type::DOUBLE, Type::BYTE_ARRAY, Type::FIXED_LEN_BYTE_ARRAY
    };
    
    // Test that every enum value can be converted to string and back
    for (auto type : all_types) {
        auto str = to_string(type);
        ASSERT_TRUE(str != "UNKNOWN");  // Should not return UNKNOWN for valid enum
        
        auto converted = to_datatype_enum(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(type, converted.value());
    }
}

TEST(CompressionCodecEnumCompleteness) {
    // Define all known CompressionCodec enum values
    CompressionCodec::type all_codecs[] = {
        CompressionCodec::UNCOMPRESSED, CompressionCodec::SNAPPY, CompressionCodec::GZIP,
        CompressionCodec::LZO, CompressionCodec::BROTLI, CompressionCodec::LZ4,
        CompressionCodec::ZSTD, CompressionCodec::LZ4_RAW
    };
    
    // Test that every enum value can be converted to string and back
    for (auto codec : all_codecs) {
        auto str = to_string(codec);
        ASSERT_TRUE(str != "UNKNOWN");  // Should not return UNKNOWN for valid enum
        
        auto converted = to_compression_enum(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(codec, converted.value());
    }
}

TEST(FormatEnumCompleteness) {
    // Define all known Format enum values
    Format::type all_formats[] = {
        Format::UNDEFINED, Format::PLAIN
    };
    
    // Test that every enum value can be converted to string and back
    for (auto format : all_formats) {
        auto str = to_string(format);
        ASSERT_TRUE(str != "UNKNOWN");  // Should not return UNKNOWN for valid enum
        
        auto converted = to_format_enum(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(format, converted.value());
    }
}


TEST(StringUniqueness) {
    // Test that all string representations are unique
    std::set<std::string> type_strings;
    std::set<std::string> codec_strings;
    std::set<std::string> format_strings;
    // Collect all Type strings
    Type::type all_types[] = {
        Type::BOOLEAN, Type::INT32, Type::INT64, Type::INT96,
        Type::FLOAT, Type::DOUBLE, Type::BYTE_ARRAY, Type::FIXED_LEN_BYTE_ARRAY
    };
    for (auto type : all_types) {
        type_strings.insert(std::string(to_string(type)));
    }
    ASSERT_EQ(8, type_strings.size());  // All strings should be unique
    
    // Collect all CompressionCodec strings
    CompressionCodec::type all_codecs[] = {
        CompressionCodec::UNCOMPRESSED, CompressionCodec::SNAPPY, CompressionCodec::GZIP,
        CompressionCodec::LZO, CompressionCodec::BROTLI, CompressionCodec::LZ4,
        CompressionCodec::ZSTD, CompressionCodec::LZ4_RAW
    };
    for (auto codec : all_codecs) {
        codec_strings.insert(std::string(to_string(codec)));
    }
    ASSERT_EQ(8, codec_strings.size());  // All strings should be unique
    
    // Collect all Format strings
    Format::type all_formats[] = {
        Format::UNDEFINED, Format::PLAIN
    };
    for (auto format : all_formats) {
        format_strings.insert(std::string(to_string(format)));
    }
    ASSERT_EQ(2, format_strings.size());  // All strings should be unique
    
}

TEST(CrossEnumStringCollision) {
    // Test that strings from different enums don't collide
    std::set<std::string> all_strings;
    
    // Collect all strings from all enums
    Type::type all_types[] = {
        Type::BOOLEAN, Type::INT32, Type::INT64, Type::INT96,
        Type::FLOAT, Type::DOUBLE, Type::BYTE_ARRAY, Type::FIXED_LEN_BYTE_ARRAY
    };
    for (auto type : all_types) {
        all_strings.insert(std::string(to_string(type)));
    }
    
    CompressionCodec::type all_codecs[] = {
        CompressionCodec::UNCOMPRESSED, CompressionCodec::SNAPPY, CompressionCodec::GZIP,
        CompressionCodec::LZO, CompressionCodec::BROTLI, CompressionCodec::LZ4,
        CompressionCodec::ZSTD, CompressionCodec::LZ4_RAW
    };
    for (auto codec : all_codecs) {
        all_strings.insert(std::string(to_string(codec)));
    }
    
    Format::type all_formats[] = {
        Format::UNDEFINED, Format::PLAIN
    };
    for (auto format : all_formats) {
        all_strings.insert(std::string(to_string(format)));
    }
    
    // Total should be 8 + 8 + 2 = 18 unique strings
    ASSERT_EQ(18, all_strings.size());
}

int main() {
    std::cout << "Running Enum Utils Tests..." << std::endl;
    
    // Type enum tests
    test_TypeToStringConversion();
    test_TypeFromStringConversion();
    test_TypeInvalidFromString();
    
    // CompressionCodec enum tests
    test_CompressionCodecToStringConversion();
    test_CompressionCodecFromStringConversion();
    test_CompressionCodecInvalidFromString();
    
    // Format enum tests
    test_FormatToStringConversion();
    test_FormatFromStringConversion();
    test_FormatInvalidFromString();
    
    
    // Round-trip tests
    test_RoundTripTypeConversion();
    test_RoundTripCompressionCodecConversion();
    test_RoundTripFormatConversion();
    
    // Edge case tests
    test_EmptyStringHandling();
    test_WhitespaceHandling();
    test_CaseSensitivity();
    test_StringViewCompatibility();
    test_RuntimeEvaluation();
    
    // Protection tests
    test_TypeEnumCompleteness();
    test_CompressionCodecEnumCompleteness();
    test_FormatEnumCompleteness();
    test_StringUniqueness();
    test_CrossEnumStringCollision();
    
    std::cout << "All enum utils tests passed!" << std::endl;
    return 0;
}
