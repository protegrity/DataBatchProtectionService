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

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include <utility>
#include <functional>

// For TypedListValues type
#include "../server/decoding_utils.h"

namespace dbps::value_encryption_utils {

/**
 * Simple container for an encrypted payload and its size.
 */
struct EncryptedValue {
    std::vector<uint8_t> payload;
    std::size_t size;
};

/**
 * Concatenate a list of EncryptedValue into a single binary blob:
 * - int32 (LE) number of elements
 * - for each element:
 *   - int32 (LE) size
 *   - payload bytes
 *
 * @throws std::overflow_error if count or any size doesn't fit in uint32_t
 */
std::vector<uint8_t> ConcatenateEncryptedValues(const std::vector<EncryptedValue>& values);

/**
 * Parse a concatenated blob produced by ConcatenateEncryptedValues into a list
 * of EncryptedValue entries.
 *
 * Format:
 * - int32 (LE) number of elements
 * - for each element:
 *   - int32 (LE) size
 *   - payload bytes
 *
 * @throws std::runtime_error on malformed input (truncated or inconsistent sizes)
 */
std::vector<EncryptedValue> ParseConcatenatedEncryptedValues(const std::vector<uint8_t>& blob);

/**
 * Encrypt each element contained across a list of TypedListValues.
 * Steps:
 *  - For each TypedListValues entry, iterate its contained vector of typed elements
 *  - Serialize each element into a byte array (little-endian for numeric types)
  *  - Concatenate all EncryptedValue records with ConcatenateEncryptedValues
 *
 * @param elements Vector of TypedListValues variants
 * @return Concatenated binary blob of encrypted, length-prefixed element payloads
 */
 // Single TypedListValues input

/**
 * Same as EncryptTypedListValues but allows injecting a custom byte-array
 * encryption routine. 
 */
std::vector<EncryptedValue> EncryptTypedListValues(
    const TypedListValues& elements,
    const std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)>& encrypt_byte_array);

/**
 * Inverse of EncryptTypedListValues (callback overload).
 * Takes a list of EncryptedValue entries, decrypts each with the provided byte-array
 * decrypt function, deserializes according to the provided datatype, and aggregates
 * them into a single TypedListValues.
 *
 * @param encrypted_values List of encrypted values with payload and declared size
 * @param datatype Data type of the elements (dbps::external::Type)
 * @param decrypt_byte_array Callback to decrypt a byte-array
 * @return TypedListValues containing the decrypted elements
 */
TypedListValues DecryptTypedListValues(
    const std::vector<EncryptedValue>& encrypted_values,
    Type::type datatype,
    const std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)>& decrypt_byte_array);
} // namespace dbps::value_encryption_utils
