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
#include <cstdlib>
#include <chrono>
#include <cstring>
#include <limits>
#include "../value_encryption_utils.h"

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

    bool ShouldLogValueEncryption() {
        return false;
        // const char* env = std::getenv("DBPS_LOG_VALUE_ENCRYPTION");
        // return env != nullptr && std::string(env) == "1";
    }

    bool ShouldLogValueEncryptionTiming() {
        const char* env = std::getenv("DBPS_LOG_VALUE_ENCRYPT_TIMING");
        return env == nullptr || std::string(env) == "1";
    }

    void EncryptBytesInto(const uint8_t* data, size_t len, const std::string& key_id, uint8_t* out) {
        if (len == 0) {
            return;
        }
        if (key_id.empty()) {
            throw std::invalid_argument("EncryptBytesInto: key must not be empty for non-empty data");
        }

        std::hash<std::string> hasher;
        size_t key_hash = hasher(key_id);
        for (size_t i = 0; i < len; ++i) {
            out[i] = data[i] ^ (key_hash & 0xFF);
            key_hash = (key_hash << 1) | (key_hash >> 31);
        }
    }
}

std::vector<uint8_t> BasicEncryptor::EncryptBlock(const std::vector<uint8_t>& data) {
	return EncryptByteArray(data, key_id_);
}

std::vector<uint8_t> BasicEncryptor::DecryptBlock(const std::vector<uint8_t>& data) {
    // For XOR encryption, decryption is the same as encryption
    return DecryptByteArray(data, key_id_);
}

std::vector<uint8_t> BasicEncryptor::EncryptValueList_OLD(
    const TypedListValues& typed_list) {

    const bool log_timings = ShouldLogValueEncryptionTiming();
    using Clock = std::chrono::steady_clock;
    std::vector<std::pair<std::string, long long>> timings;

    auto time_step = [&](const char* label, const std::function<void()>& fn) {
        if (!log_timings) {
            fn();
            return;
        }
        auto start = Clock::now();
        fn();
        auto end = Clock::now();
        auto micros = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        timings.emplace_back(label, micros);
    };

    if (ShouldLogValueEncryption()) {
        // Printout the typed list.
        auto print_result = TypedListToString(typed_list);
        if (print_result.length() > 1000) {
            std::cout << "Encrypt value - Decoded plaintext data (first 1000 chars):\n"
                      << print_result.substr(0, 1000) << "...\n";
        } else {
            std::cout << "Encrypt value - Decoded plaintext data:\n" << print_result << "\n";
        }

        // Printout the additional context parameters.
        std::cout << "Context parameters:\n"
                  << "  column_name: " << column_name_ << "\n"
                  << "  user_id: " << user_id_ << "\n"
                  << "  key_id: " << key_id_ << "\n"
                  << "  application_context: " << application_context_ << "\n"
                  << "  datatype: " << dbps::enum_utils::to_string(datatype_) << "\n";
    }

    // create a closure for the encrypt function (to be used below)
    // the closure captures the key_bytes and calls the EncryptByteArray function.
	const std::string key_id_copy = key_id_;
	auto encrypt_function = [key_id_copy](const std::vector<uint8_t>& in) -> std::vector<uint8_t> {
		return EncryptByteArray(in, key_id_copy);
	};

    // here begins the actual encryption logic.

    // (1) encrypt the list of values. Each element in the list is encrypted separately 
    // using the key and the EncryptByteArray function.
    
    std::vector<EncryptedValue> encrypted_values;
    time_step("EncryptTypedListValues", [&]() {
        encrypted_values = EncryptTypedListValues(
            typed_list,
            encrypt_function);
    });

    // (2) concatenate the encrypted values into a single byte blob.
    // (the blob encodes #of elements and the size of each element)
    std::vector<uint8_t> concatenated_encrypted_bytes;
    time_step("ConcatenateEncryptedValues", [&]() {
        concatenated_encrypted_bytes = ConcatenateEncryptedValues(encrypted_values);
    });

    if (log_timings) {
        std::cout << "EncryptValueList timings (microseconds):\n";
        for (const auto& entry : timings) {
            std::cout << "  " << entry.first << ": " << entry.second << "\n";
        }
    }
    
    return concatenated_encrypted_bytes;
} // EncryptValueList

std::vector<uint8_t> BasicEncryptor::EncryptValueList(
    const TypedListValues& typed_list) {

    const bool log_timings = ShouldLogValueEncryptionTiming();
    using Clock = std::chrono::steady_clock;
    std::vector<std::pair<std::string, long long>> timings;

    auto time_step = [&](const char* label, const std::function<void()>& fn) {
        if (!log_timings) {
            fn();
            return;
        }
        auto start = Clock::now();
        fn();
        auto end = Clock::now();
        auto micros = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        timings.emplace_back(label, micros);
    };

    if (ShouldLogValueEncryption()) {
        // Printout the typed list.
        auto print_result = TypedListToString(typed_list);
        if (print_result.length() > 1000) {
            std::cout << "Encrypt value - Decoded plaintext data (first 1000 chars):\n"
                      << print_result.substr(0, 1000) << "...\n";
        } else {
            std::cout << "Encrypt value - Decoded plaintext data:\n" << print_result << "\n";
        }

        // Printout the additional context parameters.
        std::cout << "Context parameters:\n"
                  << "  column_name: " << column_name_ << "\n"
                  << "  user_id: " << user_id_ << "\n"
                  << "  key_id: " << key_id_ << "\n"
                  << "  application_context: " << application_context_ << "\n"
                  << "  datatype: " << dbps::enum_utils::to_string(datatype_) << "\n";
    }

    const std::string key_id_copy = key_id_;
    std::vector<uint8_t> concatenated_encrypted_bytes;

    size_t total_capacity = 0;
    uint32_t count = 0;

    time_step("ComputeEncryptedSize", [&]() {
        std::visit([&](const auto& vec) {
            using VecT = std::decay_t<decltype(vec)>;
            using ElemT = typename VecT::value_type;
            if (vec.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
                throw InvalidInputException("Too many elements to serialize into uint32 count");
            }
            count = static_cast<uint32_t>(vec.size());
            total_capacity = 4;
            for (size_t i = 0; i < vec.size(); ++i) {
                size_t elem_size = 0;
                if constexpr (std::is_same_v<ElemT, int32_t> || std::is_same_v<ElemT, float>) {
                    elem_size = 4;
                } else if constexpr (std::is_same_v<ElemT, int64_t> || std::is_same_v<ElemT, double>) {
                    elem_size = 8;
                } else if constexpr (std::is_same_v<ElemT, std::array<uint32_t, 3>>) {
                    elem_size = 12;
                } else if constexpr (std::is_same_v<ElemT, std::string>) {
                    elem_size = vec[i].size();
                } else {
                    static_assert(sizeof(ElemT) == 0, "Unsupported element type in TypedListValues");
                }

                if (elem_size > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
                    throw InvalidInputException("Element size exceeds uint32 capacity");
                }
                total_capacity += 4 + elem_size;
            }
        }, typed_list);
    });

    time_step("EncryptIntoBuffer", [&]() {
        concatenated_encrypted_bytes.resize(total_capacity);
        size_t offset = 0;
        auto write_u32_le = [&](uint32_t v) {
            concatenated_encrypted_bytes[offset + 0] = static_cast<uint8_t>(v & 0xFF);
            concatenated_encrypted_bytes[offset + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
            concatenated_encrypted_bytes[offset + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
            concatenated_encrypted_bytes[offset + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
            offset += 4;
        };

        write_u32_le(count);

        std::visit([&](const auto& vec) {
            using VecT = std::decay_t<decltype(vec)>;
            using ElemT = typename VecT::value_type;

            for (size_t i = 0; i < vec.size(); ++i) {
                size_t elem_size = 0;
                if constexpr (std::is_same_v<ElemT, int32_t>) {
                    elem_size = 4;
                    write_u32_le(static_cast<uint32_t>(elem_size));
                    uint8_t raw[4];
                    const uint32_t v = static_cast<uint32_t>(vec[i]);
                    raw[0] = static_cast<uint8_t>(v & 0xFF);
                    raw[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
                    raw[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
                    raw[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
                    EncryptBytesInto(raw, elem_size, key_id_copy, concatenated_encrypted_bytes.data() + offset);
                    offset += elem_size;
                } else if constexpr (std::is_same_v<ElemT, int64_t>) {
                    elem_size = 8;
                    write_u32_le(static_cast<uint32_t>(elem_size));
                    uint8_t raw[8];
                    const uint64_t v = static_cast<uint64_t>(vec[i]);
                    raw[0] = static_cast<uint8_t>(v & 0xFF);
                    raw[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
                    raw[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
                    raw[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
                    raw[4] = static_cast<uint8_t>((v >> 32) & 0xFF);
                    raw[5] = static_cast<uint8_t>((v >> 40) & 0xFF);
                    raw[6] = static_cast<uint8_t>((v >> 48) & 0xFF);
                    raw[7] = static_cast<uint8_t>((v >> 56) & 0xFF);
                    EncryptBytesInto(raw, elem_size, key_id_copy, concatenated_encrypted_bytes.data() + offset);
                    offset += elem_size;
                } else if constexpr (std::is_same_v<ElemT, float>) {
                    elem_size = 4;
                    write_u32_le(static_cast<uint32_t>(elem_size));
                    uint32_t bits = 0;
                    std::memcpy(&bits, &vec[i], sizeof(bits));
                    uint8_t raw[4];
                    raw[0] = static_cast<uint8_t>(bits & 0xFF);
                    raw[1] = static_cast<uint8_t>((bits >> 8) & 0xFF);
                    raw[2] = static_cast<uint8_t>((bits >> 16) & 0xFF);
                    raw[3] = static_cast<uint8_t>((bits >> 24) & 0xFF);
                    EncryptBytesInto(raw, elem_size, key_id_copy, concatenated_encrypted_bytes.data() + offset);
                    offset += elem_size;
                } else if constexpr (std::is_same_v<ElemT, double>) {
                    elem_size = 8;
                    write_u32_le(static_cast<uint32_t>(elem_size));
                    uint64_t bits = 0;
                    std::memcpy(&bits, &vec[i], sizeof(bits));
                    uint8_t raw[8];
                    raw[0] = static_cast<uint8_t>(bits & 0xFF);
                    raw[1] = static_cast<uint8_t>((bits >> 8) & 0xFF);
                    raw[2] = static_cast<uint8_t>((bits >> 16) & 0xFF);
                    raw[3] = static_cast<uint8_t>((bits >> 24) & 0xFF);
                    raw[4] = static_cast<uint8_t>((bits >> 32) & 0xFF);
                    raw[5] = static_cast<uint8_t>((bits >> 40) & 0xFF);
                    raw[6] = static_cast<uint8_t>((bits >> 48) & 0xFF);
                    raw[7] = static_cast<uint8_t>((bits >> 56) & 0xFF);
                    EncryptBytesInto(raw, elem_size, key_id_copy, concatenated_encrypted_bytes.data() + offset);
                    offset += elem_size;
                } else if constexpr (std::is_same_v<ElemT, std::array<uint32_t, 3>>) {
                    elem_size = 12;
                    write_u32_le(static_cast<uint32_t>(elem_size));
                    uint8_t raw[12];
                    for (int j = 0; j < 3; ++j) {
                        const uint32_t w = vec[i][j];
                        raw[j * 4 + 0] = static_cast<uint8_t>(w & 0xFF);
                        raw[j * 4 + 1] = static_cast<uint8_t>((w >> 8) & 0xFF);
                        raw[j * 4 + 2] = static_cast<uint8_t>((w >> 16) & 0xFF);
                        raw[j * 4 + 3] = static_cast<uint8_t>((w >> 24) & 0xFF);
                    }
                    EncryptBytesInto(raw, elem_size, key_id_copy, concatenated_encrypted_bytes.data() + offset);
                    offset += elem_size;
                } else if constexpr (std::is_same_v<ElemT, std::string>) {
                    elem_size = vec[i].size();
                    write_u32_le(static_cast<uint32_t>(elem_size));
                    if (elem_size > 0) {
                        EncryptBytesInto(reinterpret_cast<const uint8_t*>(vec[i].data()),
                                         elem_size,
                                         key_id_copy,
                                         concatenated_encrypted_bytes.data() + offset);
                        offset += elem_size;
                    }
                } else {
                    static_assert(sizeof(ElemT) == 0, "Unsupported element type in TypedListValues");
                }
            }
        }, typed_list);
    });

    if (log_timings) {
        std::cout << "EncryptValueList timings (microseconds):\n";
        for (const auto& entry : timings) {
            std::cout << "  " << entry.first << ": " << entry.second << "\n";
        }
    }

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
