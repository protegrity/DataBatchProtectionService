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
#include "../../common/exceptions.h"
#include "../../common/enum_utils.h"
#include <functional>
#include <iostream>
#include "../../common/value_encryption_utils.h"

using namespace dbps::value_encryption_utils;

namespace {
	std::vector<uint8_t> EncryptByteArray(const std::vector<uint8_t>& data, const std::string& key_id) {
		if (data.empty()) {
			return std::vector<uint8_t>();
		}
		if (key_id.empty()) {
			throw std::invalid_argument("EncryptByteArray: key must not be empty for non-empty data");
		}

        std::vector<uint8_t> encrypted_data(data.size());

        // Generate a simple key from key_id by hashing it
        std::hash<std::string> hasher;
        size_t key_hash = hasher(key_id);
        
        // XOR each byte with the key hash
        for (size_t i = 0; i < data.size(); ++i) {
            encrypted_data[i] = data[i] ^ (key_hash & 0xFF);
            // Rotate the key hash for next byte
            key_hash = (key_hash << 1) | (key_hash >> 31);
        }

        return encrypted_data;
	}

    std::vector<uint8_t> DecryptByteArray(const std::vector<uint8_t>& data, const std::string& key_id) {
        return EncryptByteArray(data, key_id); // for XOR encryption, decryption is the same as encryption
    }
}

std::vector<uint8_t> BasicEncryptor::EncryptBlock(const std::vector<uint8_t>& data) {
	return EncryptByteArray(data, key_id_);
}

std::vector<uint8_t> BasicEncryptor::DecryptBlock(const std::vector<uint8_t>& data) {
    // For XOR encryption, decryption is the same as encryption
    return DecryptByteArray(data, key_id_);
}

std::vector<uint8_t> BasicEncryptor::EncryptValueList(
    const TypedListValues& typed_list) {

    // Printout the typed list.
    auto print_result = TypedListToString(typed_list);
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
              << "  datatype: " << dbps::enum_utils::to_string(datatype_) << "\n"
              << std::endl;

    // create a closure for the encrypt function (to be used below)
    // the closure captures the key_bytes and calls the EncryptByteArray function.
	const std::string key_id_copy = key_id_;
	auto encrypt_function = [key_id_copy](const std::vector<uint8_t>& in) -> std::vector<uint8_t> {
		return EncryptByteArray(in, key_id_copy);
	};

    // here begins the actual encryption logic.

    // (1) encrypt the list of values. Each element in the list is encrypted separately 
    // using the key and the EncryptByteArray function.
    
    std::vector<EncryptedValue> encrypted_values = EncryptTypedListValues(
        typed_list, 
        encrypt_function);

    // (2) concatenate the encrypted values into a single byte blob.
    // (the blob encodes #of elements and the size of each element)
    std::vector<uint8_t> concatenated_encrypted_bytes = ConcatenateEncryptedValues(encrypted_values);
    
    return concatenated_encrypted_bytes;
} // EncryptValueList

TypedListValues BasicEncryptor::DecryptValueList(
    const std::vector<uint8_t>& encrypted_bytes) {

    // create a closure for the decrypt function (to be used below)
    // the closure captures the key_bytes and calls the DecryptByteArray function.
	const std::string key_id_copy = key_id_;
	auto decrypt_function = [key_id_copy](const std::vector<uint8_t>& in) -> std::vector<uint8_t> {
		return DecryptByteArray(in, key_id_copy);
	};

    // here begins the actual decryption logic.

    // (1) parse the encrypted bytes (blob) into a list of EncryptedValue elements.
    std::vector<EncryptedValue> encrypted_values = ParseConcatenatedEncryptedValues(encrypted_bytes);

    // (2) decrypt the list of values. Each element in the list is decrypted separately 
    // using the key and the DecryptByteArray function.
    TypedListValues decrypted_values = DecryptTypedListValues(
        encrypted_values, 
        datatype_,
        decrypt_function);

    return decrypted_values;
}
