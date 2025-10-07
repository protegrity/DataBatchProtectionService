#include "dbpa_utils.h"
#include <gtest/gtest.h>
#include <map>
#include <string>

using namespace dbps::external;

// Test ExtractServerUrl function
TEST(DBPAUtilsTest, ExtractServerUrl_ValidUrl) {
    std::map<std::string, std::string> connection_config = {{"server_url", "http://localhost:8080"}};
    auto result = ExtractServerUrl(connection_config);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), "http://localhost:8080");
}

TEST(DBPAUtilsTest, ExtractServerUrl_ValidUrlWithOtherFields) {
    std::map<std::string, std::string> connection_config = {
        {"server_url", "https://example.com:443"},
        {"timeout", "30"},
        {"retry_count", "3"}
    };
    auto result = ExtractServerUrl(connection_config);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), "https://example.com:443");
}

TEST(DBPAUtilsTest, ExtractServerUrl_MissingServerUrl) {
    std::map<std::string, std::string> connection_config = {
        {"timeout", "30"},
        {"retry_count", "3"}
    };
    auto result = ExtractServerUrl(connection_config);
    
    EXPECT_FALSE(result.has_value());
}

TEST(DBPAUtilsTest, ExtractServerUrl_EmptyMap) {
    std::map<std::string, std::string> connection_config;
    auto result = ExtractServerUrl(connection_config);
    
    EXPECT_FALSE(result.has_value());
}

TEST(DBPAUtilsTest, ExtractServerUrl_EmptyValue) {
    std::map<std::string, std::string> connection_config = {{"server_url", ""}};
    auto result = ExtractServerUrl(connection_config);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), "");
}

// Test ExtractUserId function
TEST(DBPAUtilsTest, ExtractUserId_ValidJson) {
    std::string app_context = R"({"user_id": "test_user_123"})";
    auto result = ExtractUserId(app_context);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), "test_user_123");
}

TEST(DBPAUtilsTest, ExtractUserId_ValidJsonWithExtraFields) {
    std::string app_context = R"({"user_id": "alice", "role": "admin", "tenant": "company_a"})";
    auto result = ExtractUserId(app_context);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), "alice");
}

TEST(DBPAUtilsTest, ExtractUserId_MissingUserIdField) {
    std::string app_context = R"({"role": "admin", "tenant": "company_a"})";
    auto result = ExtractUserId(app_context);
    
    EXPECT_FALSE(result.has_value());
}

TEST(DBPAUtilsTest, ExtractUserId_EmptyUserIdValue) {
    std::string app_context = R"({"user_id": ""})";
    auto result = ExtractUserId(app_context);
    
    EXPECT_FALSE(result.has_value());
}

TEST(DBPAUtilsTest, ExtractUserId_UserIdNotString) {
    std::string app_context = R"({"user_id": 12345})";
    auto result = ExtractUserId(app_context);
    
    EXPECT_FALSE(result.has_value());
}

TEST(DBPAUtilsTest, ExtractUserId_InvalidJson) {
    std::string app_context = "not valid json {{{";
    auto result = ExtractUserId(app_context);
    
    EXPECT_FALSE(result.has_value());
}

TEST(DBPAUtilsTest, ExtractUserId_EmptyString) {
    std::string app_context = "";
    auto result = ExtractUserId(app_context);
    
    EXPECT_FALSE(result.has_value());
}

TEST(DBPAUtilsTest, ExtractUserId_ValidJsonArray) {
    std::string app_context = R"([{"user_id": "test"}])";
    auto result = ExtractUserId(app_context);
    
    EXPECT_FALSE(result.has_value());
}

// Test ExtractPageEncoding function
TEST(DBPAUtilsTest, ExtractPageEncoding_ValidPlainEncoding) {
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}};
    auto result = ExtractPageEncoding(encoding_attributes);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), Format::PLAIN);
}

TEST(DBPAUtilsTest, ExtractPageEncoding_ValidRLEEncoding) {
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "RLE"}};
    auto result = ExtractPageEncoding(encoding_attributes);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), Format::RLE);
}

TEST(DBPAUtilsTest, ExtractPageEncoding_ValidDeltaBinaryPackedEncoding) {
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "DELTA_BINARY_PACKED"}};
    auto result = ExtractPageEncoding(encoding_attributes);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), Format::DELTA_BINARY_PACKED);
}

TEST(DBPAUtilsTest, ExtractPageEncoding_WithOtherAttributes) {
    std::map<std::string, std::string> encoding_attributes = {
        {"page_type", "DATA_PAGE_V2"},
        {"page_encoding", "PLAIN"},
        {"data_page_num_values", "100"}
    };
    auto result = ExtractPageEncoding(encoding_attributes);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), Format::PLAIN);
}

TEST(DBPAUtilsTest, ExtractPageEncoding_MissingPageEncodingKey) {
    std::map<std::string, std::string> encoding_attributes = {
        {"page_type", "DATA_PAGE_V2"},
        {"data_page_num_values", "100"}
    };
    auto result = ExtractPageEncoding(encoding_attributes);
    
    EXPECT_FALSE(result.has_value());
}

TEST(DBPAUtilsTest, ExtractPageEncoding_EmptyMap) {
    std::map<std::string, std::string> encoding_attributes;
    auto result = ExtractPageEncoding(encoding_attributes);
    
    EXPECT_FALSE(result.has_value());
}

TEST(DBPAUtilsTest, ExtractPageEncoding_InvalidEncodingValue) {
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "INVALID_FORMAT"}};
    auto result = ExtractPageEncoding(encoding_attributes);
    
    EXPECT_FALSE(result.has_value());
}

TEST(DBPAUtilsTest, ExtractPageEncoding_EmptyEncodingValue) {
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", ""}};
    auto result = ExtractPageEncoding(encoding_attributes);
    
    EXPECT_FALSE(result.has_value());
}

TEST(DBPAUtilsTest, ExtractPageEncoding_CaseSensitivity) {
    // Assuming the to_format_enum is case-sensitive
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "plain"}};
    auto result = ExtractPageEncoding(encoding_attributes);
    
    // This test depends on whether to_format_enum is case-sensitive
    // If it's case-sensitive, this should fail
    // Adjust expectation based on actual implementation
    EXPECT_FALSE(result.has_value());
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

