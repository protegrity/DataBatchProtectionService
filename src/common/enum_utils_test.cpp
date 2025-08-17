#include "enum_utils.h"
#include <iostream>
#include <cassert>

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
    auto result = from_string_type("BOOLEAN");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::BOOLEAN, result.value());
    
    result = from_string_type("INT32");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::INT32, result.value());
    
    result = from_string_type("INT64");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::INT64, result.value());
    
    result = from_string_type("INT96");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::INT96, result.value());
    
    result = from_string_type("FLOAT");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::FLOAT, result.value());
    
    result = from_string_type("DOUBLE");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::DOUBLE, result.value());
    
    result = from_string_type("BYTE_ARRAY");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::BYTE_ARRAY, result.value());
    
    result = from_string_type("FIXED_LEN_BYTE_ARRAY");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::FIXED_LEN_BYTE_ARRAY, result.value());
}

TEST(TypeInvalidFromString) {
    auto result = from_string_type("INVALID");
    ASSERT_FALSE(result.has_value());
    
    result = from_string_type("boolean");  // lowercase
    ASSERT_FALSE(result.has_value());
    
    result = from_string_type("BYTEARRAY");  // missing underscore
    ASSERT_FALSE(result.has_value());
    
    result = from_string_type("");
    ASSERT_FALSE(result.has_value());
    
    result = from_string_type("UNKNOWN");
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
    auto result = from_string_codec("UNCOMPRESSED");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::UNCOMPRESSED, result.value());
    
    result = from_string_codec("SNAPPY");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::SNAPPY, result.value());
    
    result = from_string_codec("GZIP");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::GZIP, result.value());
    
    result = from_string_codec("LZO");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::LZO, result.value());
    
    result = from_string_codec("BROTLI");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::BROTLI, result.value());
    
    result = from_string_codec("LZ4");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::LZ4, result.value());
    
    result = from_string_codec("ZSTD");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::ZSTD, result.value());
    
    result = from_string_codec("LZ4_RAW");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(CompressionCodec::LZ4_RAW, result.value());
}

TEST(CompressionCodecInvalidFromString) {
    auto result = from_string_codec("INVALID");
    ASSERT_FALSE(result.has_value());
    
    result = from_string_codec("gzip");  // lowercase
    ASSERT_FALSE(result.has_value());
    
    result = from_string_codec("LZ4RAW");  // missing underscore
    ASSERT_FALSE(result.has_value());
    
    result = from_string_codec("");
    ASSERT_FALSE(result.has_value());
    
    result = from_string_codec("NONE");  // common alternative
    ASSERT_FALSE(result.has_value());
}

// Test Format enum conversions
TEST(FormatToStringConversion) {
    ASSERT_EQ("JSON", std::string(to_string(Format::JSON)));
    ASSERT_EQ("CSV", std::string(to_string(Format::CSV)));
    ASSERT_EQ("RAW_C_DATA", std::string(to_string(Format::RAW_C_DATA)));
}

TEST(FormatFromStringConversion) {
    auto result = from_string_format("JSON");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::JSON, result.value());
    
    result = from_string_format("CSV");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::CSV, result.value());
    
    result = from_string_format("RAW_C_DATA");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Format::RAW_C_DATA, result.value());
}

TEST(FormatInvalidFromString) {
    auto result = from_string_format("INVALID");
    ASSERT_FALSE(result.has_value());
    
    result = from_string_format("json");  // lowercase
    ASSERT_FALSE(result.has_value());
    
    result = from_string_format("RAWC_DATA");  // missing underscore
    ASSERT_FALSE(result.has_value());
    
    result = from_string_format("");
    ASSERT_FALSE(result.has_value());
    
    result = from_string_format("XML");  // common format
    ASSERT_FALSE(result.has_value());
}

// Test Encoding enum conversions
TEST(EncodingToStringConversion) {
    ASSERT_EQ("UTF8", std::string(to_string(Encoding::UTF8)));
    ASSERT_EQ("BASE64", std::string(to_string(Encoding::BASE64)));
}

TEST(EncodingFromStringConversion) {
    auto result = from_string_encoding("UTF8");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Encoding::UTF8, result.value());
    
    result = from_string_encoding("BASE64");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Encoding::BASE64, result.value());
}

TEST(EncodingInvalidFromString) {
    auto result = from_string_encoding("INVALID");
    ASSERT_FALSE(result.has_value());
    
    result = from_string_encoding("utf8");  // lowercase
    ASSERT_FALSE(result.has_value());
    
    result = from_string_encoding("UTF-8");  // with hyphen
    ASSERT_FALSE(result.has_value());
    
    result = from_string_encoding("");
    ASSERT_FALSE(result.has_value());
    
    result = from_string_encoding("ASCII");  // common encoding
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
        auto converted = from_string_type(str);
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
        auto converted = from_string_codec(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(codec, converted.value());
    }
}

TEST(RoundTripFormatConversion) {
    // Test all Format enum values
    Format::type formats[] = {
        Format::JSON, Format::CSV, Format::RAW_C_DATA
    };
    
    for (auto format : formats) {
        auto str = to_string(format);
        auto converted = from_string_format(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(format, converted.value());
    }
}

TEST(RoundTripEncodingConversion) {
    // Test all Encoding enum values
    Encoding::type encodings[] = {
        Encoding::UTF8, Encoding::BASE64
    };
    
    for (auto encoding : encodings) {
        auto str = to_string(encoding);
        auto converted = from_string_encoding(str);
        ASSERT_TRUE(converted.has_value());
        ASSERT_EQ(encoding, converted.value());
    }
}

// Test edge cases
TEST(EmptyStringHandling) {
    ASSERT_FALSE(from_string_type("").has_value());
    ASSERT_FALSE(from_string_codec("").has_value());
    ASSERT_FALSE(from_string_format("").has_value());
    ASSERT_FALSE(from_string_encoding("").has_value());
}

TEST(WhitespaceHandling) {
    ASSERT_FALSE(from_string_type(" BYTE_ARRAY").has_value());
    ASSERT_FALSE(from_string_type("BYTE_ARRAY ").has_value());
    ASSERT_FALSE(from_string_type(" BYTE_ARRAY ").has_value());
    
    ASSERT_FALSE(from_string_codec(" GZIP").has_value());
    ASSERT_FALSE(from_string_codec("GZIP ").has_value());
    ASSERT_FALSE(from_string_codec(" GZIP ").has_value());
}

TEST(CaseSensitivity) {
    // Test that conversions are case-sensitive
    ASSERT_FALSE(from_string_type("byte_array").has_value());
    ASSERT_FALSE(from_string_type("Byte_Array").has_value());
    ASSERT_FALSE(from_string_type("BYTE_array").has_value());
    
    ASSERT_FALSE(from_string_codec("gzip").has_value());
    ASSERT_FALSE(from_string_codec("Gzip").has_value());
    ASSERT_FALSE(from_string_codec("GZIp").has_value());
}

TEST(StringViewCompatibility) {
    // Test that string_view works correctly
    std::string_view type_str = "BYTE_ARRAY";
    auto result = from_string_type(type_str);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(Type::BYTE_ARRAY, result.value());
    
    std::string_view codec_str = "GZIP";
    auto codec_result = from_string_codec(codec_str);
    ASSERT_TRUE(codec_result.has_value());
    ASSERT_EQ(CompressionCodec::GZIP, codec_result.value());
}

// Test runtime evaluation
TEST(RuntimeEvaluation) {
    // Test runtime evaluation of the functions
    auto type_str = to_string(Type::BYTE_ARRAY);
    auto codec_str = to_string(CompressionCodec::GZIP);
    auto format_str = to_string(Format::CSV);
    auto encoding_str = to_string(Encoding::UTF8);
    
    // Verify the results
    ASSERT_EQ("BYTE_ARRAY", std::string(type_str));
    ASSERT_EQ("GZIP", std::string(codec_str));
    ASSERT_EQ("CSV", std::string(format_str));
    ASSERT_EQ("UTF8", std::string(encoding_str));
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
    
    // Encoding enum tests
    test_EncodingToStringConversion();
    test_EncodingFromStringConversion();
    test_EncodingInvalidFromString();
    
    // Round-trip tests
    test_RoundTripTypeConversion();
    test_RoundTripCompressionCodecConversion();
    test_RoundTripFormatConversion();
    test_RoundTripEncodingConversion();
    
    // Edge case tests
    test_EmptyStringHandling();
    test_WhitespaceHandling();
    test_CaseSensitivity();
    test_StringViewCompatibility();
    test_RuntimeEvaluation();
    
    std::cout << "All enum utils tests passed!" << std::endl;
    return 0;
}
