#include "decoding_utils.h"
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <cassert>

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

    auto s = PrintPlainDecoded(buf, Type::INT32, std::nullopt, 0);
    assert(contains(s, "[0] 1"));
    assert(contains(s, "[1] -2"));
    assert(contains(s, "[2] 123456789"));
}

static void test_INT64_ok() {
    std::vector<uint8_t> buf;
    append_le<int64_t>(buf, 42LL);
    append_le<int64_t>(buf, -99LL);
    auto s = PrintPlainDecoded(buf, Type::INT64, std::nullopt, 0);
    assert(contains(s, "[0] 42"));
    assert(contains(s, "[1] -99"));
}

static void test_FLOAT_ok() {
    std::vector<uint8_t> buf;
    append_le<float>(buf, 1.5f);
    append_le<float>(buf, -2.25f);
    auto s = PrintPlainDecoded(buf, Type::FLOAT, std::nullopt, 0);
    assert(contains(s, "[0] 1.5"));
    assert(contains(s, "[1] -2.25"));
}

static void test_DOUBLE_ok() {
    std::vector<uint8_t> buf;
    append_le<double>(buf, 3.14159);
    append_le<double>(buf, -0.5);
    auto s = PrintPlainDecoded(buf, Type::DOUBLE, std::nullopt, 0);
    assert(contains(s, "[0] 3.14159"));
    assert(contains(s, "[1] -0.5"));
}

static void test_INT96_ok() {
    std::vector<uint8_t> buf;
    // one 12-byte value: lo=11, mid=22, hi=33
    append_le<uint32_t>(buf, 11);
    append_le<uint32_t>(buf, 22);
    append_le<uint32_t>(buf, 33);
    auto s = PrintPlainDecoded(buf, Type::INT96, std::nullopt, 0);
    assert(contains(s, "[0] [11, 22, 33]"));
}

static void test_BYTE_ARRAY_ok() {
    std::vector<uint8_t> buf;
    append_len_prefixed(buf, "alpha");
    append_len_prefixed(buf, "βeta"); // UTF-8 is fine, treated as bytes
    auto s = PrintPlainDecoded(buf, Type::BYTE_ARRAY, std::nullopt, 0);
    assert(contains(s, "[0] \"alpha\""));
    assert(contains(s, "[1] \"βeta\""));
}

static void test_FIXED_LEN_BYTE_ARRAY_ok() {
    std::string msg = "hello world";
    std::vector<uint8_t> buf(msg.begin(), msg.end());
    auto s = PrintPlainDecoded(buf, Type::FIXED_LEN_BYTE_ARRAY, 11, 0); // length = 11
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
    
    auto s = PrintPlainDecoded(buf, Type::FIXED_LEN_BYTE_ARRAY, 3, 0); // length = 3
    assert(contains(s, "[0] \"abc\""));
    assert(contains(s, "[1] \"def\""));
    assert(contains(s, "[2] \"ghi\""));
}

static void test_decode_error_misaligned() {
    std::vector<uint8_t> buf = {0x01, 0x02, 0x03}; // 3 bytes, not multiple of 4
    auto s = PrintPlainDecoded(buf, Type::INT32, std::nullopt, 0);
    assert(s == std::string("Unknown encoding"));
}

static void test_unsupported_type() {
    std::vector<uint8_t> buf; // empty is fine; we just want the type check
    auto s = PrintPlainDecoded(buf, Type::BOOLEAN, std::nullopt, 0);
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

    std::cout << "All tests passed.\n";
    return 0;
}
