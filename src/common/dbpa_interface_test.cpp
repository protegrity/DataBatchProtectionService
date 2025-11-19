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

#include "dbpa_interface.h"
#include <iostream>
#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <map>

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
    const std::optional<std::map<std::string, std::string>> encryption_metadata() const override { return std::nullopt; }
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
TEST(DBPAInterface, BasicEncryption) {
    std::vector<uint8_t> data = {1, 2, 3};
    MockEncryptionResult result(data);
    
    ASSERT_TRUE(result.success());
    ASSERT_EQ(3, result.size());
    ASSERT_EQ(1, result.ciphertext()[0]);
}

TEST(DBPAInterface, BasicDecryption) {
    std::vector<uint8_t> data = {4, 5, 6};
    MockDecryptionResult result(data);
    
    ASSERT_TRUE(result.success());
    ASSERT_EQ(3, result.size());
    ASSERT_EQ(4, result.plaintext()[0]);
}

TEST(DBPAInterface, AgentEncryptDecrypt) {
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
