#include "decoding_utils.h"
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <cassert>
#include <map>
#include <variant>

using namespace dbps::external;

// Helper function to append a value in little-endian format to a byte vector
template <typename T>
static void append_le(std::vector<uint8_t>& dst, T v) {
    static_assert(std::is_trivially_copyable<T>::value, "T must be trivially copyable");
    size_t off = dst.size();
    dst.resize(off + sizeof(T));
    std::memcpy(dst.data() + off, &v, sizeof(T)); // little-endian assumed
}

// Helper function to append a length-prefixed string to a byte vector
static void append_len_prefixed(std::vector<uint8_t>& dst, const std::string& s) {
    uint32_t len = static_cast<uint32_t>(s.size());
    append_le<uint32_t>(dst, len);
    size_t off = dst.size();
    dst.resize(off + s.size());
    std::memcpy(dst.data() + off, s.data(), s.size());
}

// Helper function to check if a string contains a substring
static bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

// ----------------- Tests -----------------
static void test_INT32_ok() {
    std::vector<uint8_t> buf;
    append_le<int32_t>(buf, 1);
    append_le<int32_t>(buf, -2);
    append_le<int32_t>(buf, 123456789);

    auto s = PrintPlainDecoded(buf, Type::INT32);
    assert(contains(s, "[0] 1"));
    assert(contains(s, "[1] -2"));
    assert(contains(s, "[2] 123456789"));
}

static void test_INT64_ok() {
    std::vector<uint8_t> buf;
    append_le<int64_t>(buf, 42LL);
    append_le<int64_t>(buf, -99LL);
    auto s = PrintPlainDecoded(buf, Type::INT64);
    assert(contains(s, "[0] 42"));
    assert(contains(s, "[1] -99"));
}

static void test_FLOAT_ok() {
    std::vector<uint8_t> buf;
    append_le<float>(buf, 1.5f);
    append_le<float>(buf, -2.25f);
    auto s = PrintPlainDecoded(buf, Type::FLOAT);
    assert(contains(s, "[0] 1.5"));
    assert(contains(s, "[1] -2.25"));
}

static void test_DOUBLE_ok() {
    std::vector<uint8_t> buf;
    append_le<double>(buf, 3.14159);
    append_le<double>(buf, -0.5);
    auto s = PrintPlainDecoded(buf, Type::DOUBLE);
    assert(contains(s, "[0] 3.14159"));
    assert(contains(s, "[1] -0.5"));
}

static void test_INT96_ok() {
    std::vector<uint8_t> buf;
    // one 12-byte value: lo=11, mid=22, hi=33
    append_le<uint32_t>(buf, 11);
    append_le<uint32_t>(buf, 22);
    append_le<uint32_t>(buf, 33);
    auto s = PrintPlainDecoded(buf, Type::INT96);
    assert(contains(s, "[0] [11, 22, 33]"));
}

static void test_BYTE_ARRAY_ok() {
    std::vector<uint8_t> buf;
    append_len_prefixed(buf, "alpha");
    append_len_prefixed(buf, "βeta"); // UTF-8 is fine, treated as bytes
    auto s = PrintPlainDecoded(buf, Type::BYTE_ARRAY);
    assert(contains(s, "[0] \"alpha\""));
    assert(contains(s, "[1] \"βeta\""));
}

static void test_FIXED_LEN_BYTE_ARRAY_ok() {
    std::string msg = "hello world";
    std::vector<uint8_t> buf(msg.begin(), msg.end());
    auto s = PrintPlainDecoded(buf, Type::FIXED_LEN_BYTE_ARRAY, 11); // length = 11
    assert(contains(s, "\"hello world\""));
}

static void test_FIXED_LEN_BYTE_ARRAY_multiple_elements() {
    // Test multiple fixed-length elements
    std::vector<uint8_t> buf;
    std::string elem1 = "abc";  // 3 chars
    std::string elem2 = "def";  // 3 chars
    std::string elem3 = "ghi";  // 3 chars
    buf.insert(buf.end(), elem1.begin(), elem1.end());
    buf.insert(buf.end(), elem2.begin(), elem2.end());
    buf.insert(buf.end(), elem3.begin(), elem3.end());
    
    auto s = PrintPlainDecoded(buf, Type::FIXED_LEN_BYTE_ARRAY, 3); // length = 3
    assert(contains(s, "[0] \"abc\""));
    assert(contains(s, "[1] \"def\""));
    assert(contains(s, "[2] \"ghi\""));
}

static void test_decode_error_misaligned() {
    std::vector<uint8_t> buf = {0x01, 0x02, 0x03}; // 3 bytes, not multiple of 4
    auto s = PrintPlainDecoded(buf, Type::INT32);
    assert(s == std::string("Unknown encoding"));
}

static void test_unsupported_type() {
    std::vector<uint8_t> buf; // empty is fine; we just want the type check
    auto s = PrintPlainDecoded(buf, Type::BOOLEAN);
    assert(s == std::string("Unsupported type"));
}

static void test_leading_bytes_to_strip_error_cases() {
    std::vector<uint8_t> buf;
    append_le<int32_t>(buf, 1);
    append_le<int32_t>(buf, 2);
    append_le<int32_t>(buf, 3);
    
    // Test negative value
    auto s1 = PrintPlainDecoded(buf, Type::INT32, std::nullopt, -1);
    assert(s1 == std::string("Number of leading bytes to strip must be >= 0"));
    
    // Test value larger than data size
    auto s2 = PrintPlainDecoded(buf, Type::INT32, std::nullopt, 20);
    assert(s2 == std::string("Number of leading bytes to strip must be < data size"));
    
    // Test value equal to data size (should also fail)
    auto s3 = PrintPlainDecoded(buf, Type::INT32, std::nullopt, 12);
    assert(s3 == std::string("Number of leading bytes to strip must be < data size"));
}

static void test_leading_bytes_to_strip_valid_case() {
    std::vector<uint8_t> buf;
    // Add some prefix bytes (5 bytes of level bytes)
    buf.insert(buf.end(), {0x01, 0x02, 0x03, 0x04, 0x05});
    append_le<int32_t>(buf, 100);
    append_le<int32_t>(buf, 200);
    append_le<int32_t>(buf, 300);
    
    auto s = PrintPlainDecoded(buf, Type::INT32, std::nullopt, 5);
    assert(contains(s, "[0] 100"));
    assert(contains(s, "[1] 200"));
    assert(contains(s, "[2] 300"));
}

// Helper function to create encoding attributes map for testing
static std::map<std::string, std::variant<int32_t, bool, std::string>> createEncodingAttribs(
    const std::string& page_type,
    const std::map<std::string, std::variant<int32_t, bool, std::string>>& additional = {}) {
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs;
    attribs["page_type"] = page_type;
    for (const auto& pair : additional) {
        attribs[pair.first] = pair.second;
    }
    return attribs;
}

static void test_CalculateLevelBytesLength_DATA_PAGE_V2() {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    // Test DATA_PAGE_V2 with specific byte lengths
    auto attribs = createEncodingAttribs("DATA_PAGE_V2", {
        {"page_v2_definition_levels_byte_length", int32_t(1)},
        {"page_v2_repetition_levels_byte_length", int32_t(3)}
    });
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == 4); // 1 + 3
}

static void test_CalculateLevelBytesLength_DICTIONARY_PAGE() {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    
    // Test DICTIONARY_PAGE (should return 0)
    auto attribs = createEncodingAttribs("DICTIONARY_PAGE");
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == 0);
}

static void test_CalculateLevelBytesLength_DATA_PAGE_V1_no_levels() {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    
    // Test DATA_PAGE_V1 with max levels = 0 (no level bytes)
    auto attribs = createEncodingAttribs("DATA_PAGE_V1", {
        {"data_page_max_repetition_level", int32_t(0)},
        {"data_page_max_definition_level", int32_t(0)}
    });
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == 0);
}

static void test_CalculateLevelBytesLength_DATA_PAGE_V1_with_levels() {
    // Create raw data with RLE level structures
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
    auto attribs = createEncodingAttribs("DATA_PAGE_V1", {
        {"data_page_max_repetition_level", int32_t(1)},  // > 0, so repetition levels present
        {"data_page_max_definition_level", int32_t(2)}   // > 0, so definition levels present
    });
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == 28); // (4+8) + (4+12) = 12 + 16 = 28
}

static void test_CalculateLevelBytesLength_DATA_PAGE_V1_invalid_encoding() {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    
    // Test DATA_PAGE_V1 with non-RLE encoding (should fail)
    auto attribs = createEncodingAttribs("DATA_PAGE_V1", {
        {"data_page_max_repetition_level", int32_t(1)},
        {"data_page_max_definition_level", int32_t(1)},
        {"page_v1_repetition_level_encoding", std::string("BIT_PACKED")},  // Not RLE
        {"page_v1_definition_level_encoding", std::string("RLE")}
    });
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == -1); // Should fail due to invalid encoding type
}

static void test_CalculateLevelBytesLength_unknown_page_type() {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03};
    
    // Test unknown page type
    auto attribs = createEncodingAttribs("UNKNOWN_PAGE_TYPE");
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == -1);
}

static void test_CalculateLevelBytesLength_invalid_total_size() {
    std::vector<uint8_t> raw = {0x01, 0x02}; // Only 2 bytes
    
    // Test DATA_PAGE_V2 with byte lengths exceeding raw data size
    auto attribs = createEncodingAttribs("DATA_PAGE_V2", {
        {"page_v2_definition_levels_byte_length", int32_t(5)},
        {"page_v2_repetition_levels_byte_length", int32_t(3)}
    });
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == -1); // Total (8 bytes) > raw size (2 bytes)
}

static void test_CalculateLevelBytesLength_negative_total_size() {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    
    // Test DATA_PAGE_V2 with negative byte lengths
    auto attribs = createEncodingAttribs("DATA_PAGE_V2", {
        {"page_v2_definition_levels_byte_length", int32_t(-1)},
        {"page_v2_repetition_levels_byte_length", int32_t(5)}
    });
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == -1); // Total (4 bytes) is negative due to -1
}

// ----------------- main -----------------
int main() {
    test_INT32_ok();
    test_INT64_ok();
    test_FLOAT_ok();
    test_DOUBLE_ok();
    test_INT96_ok();
    test_BYTE_ARRAY_ok();
    test_FIXED_LEN_BYTE_ARRAY_ok();
    test_FIXED_LEN_BYTE_ARRAY_multiple_elements();
    test_decode_error_misaligned();
    test_unsupported_type();
    test_leading_bytes_to_strip_error_cases();
    test_leading_bytes_to_strip_valid_case();
    
    // CalculateLevelBytesLength tests
    test_CalculateLevelBytesLength_DATA_PAGE_V2();
    test_CalculateLevelBytesLength_DICTIONARY_PAGE();
    test_CalculateLevelBytesLength_DATA_PAGE_V1_no_levels();
    test_CalculateLevelBytesLength_DATA_PAGE_V1_with_levels();
    test_CalculateLevelBytesLength_DATA_PAGE_V1_invalid_encoding();
    test_CalculateLevelBytesLength_unknown_page_type();
    test_CalculateLevelBytesLength_invalid_total_size();
    test_CalculateLevelBytesLength_negative_total_size();

    std::cout << "All tests passed.\n";
    return 0;
}
