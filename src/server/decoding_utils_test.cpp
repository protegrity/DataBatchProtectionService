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

static void test_CalculateLevelBytesLength_DATA_PAGE_V2() {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    // Test DATA_PAGE_V2 with specific byte lengths
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_definition_level", int32_t(2)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"page_v2_definition_levels_byte_length", int32_t(1)},
        {"page_v2_repetition_levels_byte_length", int32_t(3)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", false}
    };
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == 4); // 1 + 3
}

static void test_CalculateLevelBytesLength_DICTIONARY_PAGE() {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    
    // Test DICTIONARY_PAGE (should return 0)
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DICTIONARY_PAGE")}
    };
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == 0);
}

static void test_CalculateLevelBytesLength_DATA_PAGE_V1_no_levels() {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    
    // Test DATA_PAGE_V1 with max levels = 0 (no level bytes)
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"data_page_max_definition_level", int32_t(0)},
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };
    
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
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_repetition_level", int32_t(1)},  // > 0, so repetition levels present
        {"data_page_max_definition_level", int32_t(2)},  // > 0, so definition levels present
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == 28); // (4+8) + (4+12) = 12 + 16 = 28
}

static void test_CalculateLevelBytesLength_DATA_PAGE_V1_invalid_encoding() {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    
    // Test DATA_PAGE_V1 with non-RLE encoding (should fail)
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"data_page_max_definition_level", int32_t(1)},
        {"page_v1_repetition_level_encoding", std::string("BIT_PACKED")},  // Not RLE
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == -1); // Should fail due to invalid encoding type
}

static void test_CalculateLevelBytesLength_unknown_page_type() {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03};
    
    // Test unknown page type
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("UNKNOWN_PAGE_TYPE")}
    };
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == -1);
}

static void test_CalculateLevelBytesLength_invalid_total_size() {
    std::vector<uint8_t> raw = {0x01, 0x02}; // Only 2 bytes
    
    // Test DATA_PAGE_V2 with byte lengths exceeding raw data size
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_definition_level", int32_t(2)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"page_v2_definition_levels_byte_length", int32_t(5)},
        {"page_v2_repetition_levels_byte_length", int32_t(3)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", false}
    };
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == -1); // Total (8 bytes) > raw size (2 bytes)
}

static void test_CalculateLevelBytesLength_negative_total_size() {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    
    // Test DATA_PAGE_V2 with negative byte lengths
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_definition_level", int32_t(2)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"page_v2_definition_levels_byte_length", int32_t(-1)},
        {"page_v2_repetition_levels_byte_length", int32_t(-5)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", false}
    };
    
    int result = CalculateLevelBytesLength(raw, attribs);
    assert(result == -1); // Total (4 bytes) is negative due to -5
}

// ----------------- main -----------------
int main() {
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
