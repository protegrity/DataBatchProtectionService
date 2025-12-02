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

#include "basic_encryptor.h"
#include "../exceptions.h"
#include "../decoding_utils.h"
#include <gtest/gtest.h>
#include <vector>

TEST(BasicEncryptor, EncryptDecryptBlock_RoundTrip) {
    BasicEncryptor encryptor("test_key", "test_column", "test_user", "test_context");
    
    std::vector<uint8_t> original = {1, 2, 3, 4, 5, 10, 20, 30, 40, 50};
    std::vector<uint8_t> encrypted = encryptor.EncryptBlock(original);
    std::vector<uint8_t> decrypted = encryptor.DecryptBlock(encrypted);
    
    EXPECT_EQ(original, decrypted);
    EXPECT_NE(original, encrypted);
}

TEST(BasicEncryptor, EncryptBlock_EmptyData) {
    BasicEncryptor encryptor("test_key", "test_column", "test_user", "test_context");
    
    std::vector<uint8_t> empty;
    std::vector<uint8_t> encrypted = encryptor.EncryptBlock(empty);
    
    EXPECT_TRUE(encrypted.empty());
}

TEST(BasicEncryptor, EncryptBlock_DifferentKeys) {
    BasicEncryptor encryptor1("key1", "test_column", "test_user", "test_context");
    BasicEncryptor encryptor2("key2", "test_column", "test_user", "test_context");
    
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    std::vector<uint8_t> encrypted1 = encryptor1.EncryptBlock(data);
    std::vector<uint8_t> encrypted2 = encryptor2.EncryptBlock(data);
    
    EXPECT_NE(encrypted1, encrypted2);
}

TEST(BasicEncryptor, EncryptValueList_ThrowsException) {
    BasicEncryptor encryptor("test_key", "test_column", "test_user", "test_context");
    
    std::vector<int32_t> values = {1, 2, 3};
    TypedListValues typed_list = values;
    std::vector<uint8_t> level_bytes = {0, 1, 0};
    
    EXPECT_THROW(encryptor.EncryptValueList(typed_list, level_bytes), DBPSUnsupportedException);
}

TEST(BasicEncryptor, DecryptValueList_ThrowsException) {
    BasicEncryptor encryptor("test_key", "test_column", "test_user", "test_context");
    
    std::vector<uint8_t> encrypted_bytes = {1, 2, 3, 4, 5};
    
    EXPECT_THROW(encryptor.DecryptValueList(encrypted_bytes), DBPSUnsupportedException);
}

