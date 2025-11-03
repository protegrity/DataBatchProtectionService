#include "dbpa_interface.h"
#include <iostream>
#include <vector>
#include <memory>
#include <map>

// Simple test framework
#define TEST(name) void test_##name()
#define ASSERT_EQ(expected, actual) \
    if ((expected) != (actual)) { \
        std::cerr << "FAILED: " << __FUNCTION__ << " - " << #expected << " != " << #actual << std::endl; \
        exit(1); \
    }
#define ASSERT_TRUE(condition) \
    if (!(condition)) { \
        std::cerr << "FAILED: " << __FUNCTION__ << " - " << #condition << " is false" << std::endl; \
        exit(1); \
    }

using namespace dbps::external;

// Simple mock implementations
class MockEncryptionResult : public EncryptionResult {
private:
    std::vector<uint8_t> data_;
    bool success_;

public:
    MockEncryptionResult(std::vector<uint8_t> data, bool success = true) 
        : data_(std::move(data)), success_(success) {}

    span<const uint8_t> ciphertext() const override {
        return span<const uint8_t>(data_.data(), data_.size());
    }

    std::size_t size() const override { return data_.size(); }
    bool success() const override { return success_; }
    const std::string& error_message() const override { static std::string empty; return empty; }
    const std::map<std::string, std::string>& error_fields() const override { static std::map<std::string, std::string> empty; return empty; }
};

class MockDecryptionResult : public DecryptionResult {
private:
    std::vector<uint8_t> data_;
    bool success_;

public:
    MockDecryptionResult(std::vector<uint8_t> data, bool success = true) 
        : data_(std::move(data)), success_(success) {}

    span<const uint8_t> plaintext() const override {
        return span<const uint8_t>(data_.data(), data_.size());
    }

    std::size_t size() const override { return data_.size(); }
    bool success() const override { return success_; }
    const std::string& error_message() const override { static std::string empty; return empty; }
    const std::map<std::string, std::string>& error_fields() const override { static std::map<std::string, std::string> empty; return empty; }
};

class MockAgent : public DataBatchProtectionAgentInterface {
public:
    std::unique_ptr<EncryptionResult> Encrypt(span<const uint8_t> plaintext, std::map<std::string, std::string> encoding_attributes) override {
        // Simple mock implementation ignores encoding_attributes for now
        std::vector<uint8_t> encrypted(plaintext.size());
        for (std::size_t i = 0; i < plaintext.size(); ++i) {
            encrypted[i] = plaintext[i] + 1; // Simple mock: add 1
        }
        return std::make_unique<MockEncryptionResult>(std::move(encrypted));
    }

    std::unique_ptr<DecryptionResult> Decrypt(span<const uint8_t> ciphertext, std::map<std::string, std::string> encoding_attributes) override {
        // Simple mock implementation ignores encoding_attributes for now
        std::vector<uint8_t> decrypted(ciphertext.size());
        for (std::size_t i = 0; i < ciphertext.size(); ++i) {
            decrypted[i] = ciphertext[i] - 1; // Simple mock: subtract 1
        }
        return std::make_unique<MockDecryptionResult>(std::move(decrypted));
    }
};

// Basic tests
TEST(BasicEncryption) {
    std::vector<uint8_t> data = {1, 2, 3};
    MockEncryptionResult result(data);
    
    ASSERT_TRUE(result.success());
    ASSERT_EQ(3, result.size());
    ASSERT_EQ(1, result.ciphertext()[0]);
}

TEST(BasicDecryption) {
    std::vector<uint8_t> data = {4, 5, 6};
    MockDecryptionResult result(data);
    
    ASSERT_TRUE(result.success());
    ASSERT_EQ(3, result.size());
    ASSERT_EQ(4, result.plaintext()[0]);
}

TEST(AgentEncryptDecrypt) {
    MockAgent agent;
    std::vector<uint8_t> original = {10, 20, 30};
    
    std::map<std::string, std::string> encoding_attributes = {{"format", "PLAIN"}};
    auto encrypted = agent.Encrypt(span<const uint8_t>(original.data(), original.size()), encoding_attributes);
    ASSERT_TRUE(encrypted->success());
    
    auto decrypted = agent.Decrypt(encrypted->ciphertext(), encoding_attributes);
    ASSERT_TRUE(decrypted->success());
    
    ASSERT_EQ(original.size(), decrypted->size());
    ASSERT_EQ(10, decrypted->plaintext()[0]);
}

int main() {
    std::cout << "Running simple dpba_interface tests..." << std::endl;
    
    test_BasicEncryption();
    test_BasicDecryption();
    test_AgentEncryptDecrypt();
    
    std::cout << "All tests passed!" << std::endl;
    return 0;
}
