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
#include "../decoding_utils.h"
#include "../exceptions.h"
#include <functional>
#include <iostream>

std::vector<uint8_t> BasicEncryptor::EncryptBlock(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::vector<uint8_t>();
    }
    
    std::vector<uint8_t> encrypted_data(data.size());

    // Generate a simple key from key_id by hashing it
    std::hash<std::string> hasher;
    size_t key_hash = hasher(key_id_);
    
    // XOR each byte with the key hash
    for (size_t i = 0; i < data.size(); ++i) {
        encrypted_data[i] = data[i] ^ (key_hash & 0xFF);
        // Rotate the key hash for next byte
        key_hash = (key_hash << 1) | (key_hash >> 31);
    }

    return encrypted_data;
}

std::vector<uint8_t> BasicEncryptor::DecryptBlock(const std::vector<uint8_t>& data) {
    // For XOR encryption, decryption is the same as encryption
    return EncryptBlock(data);
}

std::vector<uint8_t> BasicEncryptor::EncryptValueList(
    const TypedListValues& typed_list) {

    // Printout the typed list.
    auto print_result = PrintTypedList(typed_list);
    if (print_result.length() > 1000) {
        std::cout << "Encrypt value - Decoded plaintext data (first 1000 chars):\n"
                  << print_result.substr(0, 1000) << "...";
    } else {
        std::cout << "Encrypt value - Decoded plaintext data:\n" << print_result;
    }

    // Printout the additional context parameters.
    std::cout << "Context parameters:\n"
              << "  column_name: " << column_name_ << "\n"
              << "  user_id: " << user_id_ << "\n"
              << "  key_id: " << key_id_ << "\n"
              << "  application_context: " << application_context_ << "\n"
              << std::endl;

    throw DBPSUnsupportedException("EncryptTypedList not implemented");
}

TypedListValues BasicEncryptor::DecryptValueList(
    const std::vector<uint8_t>& encrypted_bytes) {
    
    throw DBPSUnsupportedException("DecryptTypedList not implemented");
}
