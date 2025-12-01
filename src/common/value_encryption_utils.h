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
 * Encrypt a byte vector using a rolling XOR derived from the key and position.
 * For each byte i: out[i] = in[i] ^ key[i % key.size()]; advances one key byte per position.
 * If value is empty, returns an EncryptedValue with empty payload and size=0.
 * If value is non-empty and key is empty, throws std::invalid_argument.
 */
EncryptedValue EncryptValue(const std::vector<uint8_t>& value, const std::vector<uint8_t>& key);


/**
 * Decrypt an EncryptedValue using the same rolling XOR scheme as EncryptValue.
 * Only the first 'size' bytes of the payload are considered during decryption.
 * If size is 0, returns empty. If size>0 and key is empty, throws std::invalid_argument.
 */
std::vector<uint8_t> DecryptValue(const EncryptedValue& value, const std::vector<uint8_t>& key);

/**
 * Append buffers with length prefixes (32-bit little-endian).
 * Output format:
 * <u32 size1><buf1 bytes><u32 size2><buf2 bytes>...<u32 sizeN><bufN bytes>
 *
 * @throws std::overflow_error if any buffer size exceeds uint32_t capacity
 */
std::vector<uint8_t> ConcatenateBuffersWithLength(const std::vector<std::vector<uint8_t> >& buffers);

/**
 * Parse a blob produced by AppendBuffersWithLength back into buffers.
 * Strict parsing: consumes the blob exactly; trailing bytes cause an exception.
 *
 * @throws std::runtime_error on malformed input (truncated size/payload or trailing bytes)
 */
std::vector<std::vector<uint8_t> > ParseBuffersWithLength(const std::vector<uint8_t>& blob);

/**
 * Encrypt each element contained across a list of TypedListValues.
 * Steps:
 *  - For each TypedListValues entry, iterate its contained vector of typed elements
 *  - Serialize each element into a byte array (little-endian for numeric types)
 *  - Encrypt each element's bytes with EncryptValue
 *  - Concatenate all EncryptedValue records with ConcatenateEncryptedValues
 *
 * @param elements Vector of TypedListValues variants
 * @param key Byte-array key for XOR encryption (cycled per byte)
 * @return Concatenated binary blob of encrypted, length-prefixed element payloads
 */
// Single TypedListValues input
std::vector<uint8_t> EncryptTypedListValues(
    const TypedListValues& elements,
    const std::vector<uint8_t>& key);
/**
 * Variant of EncryptTypedListValues that also prefixes the resulting encrypted values
 * alongside provided level bytes using ConcatenateBuffersWithLength:
 *   buffers = [encrypted_values_blob, level_bytes]
 */
std::vector<uint8_t> EncryptTypedListValuesWithLevelBytes(
    const TypedListValues& elements,
    const std::vector<uint8_t>& level_bytes,
    const std::vector<uint8_t>& key);

/**
 * Reverse of EncryptTypedListValuesWithLevelBytes.
 * Splits combined blob into [encrypted_values_blob, level_bytes], then decrypts and
 * converts encrypted values into a TypedListValues according to the given datatype.
 *
 * @return pair { decrypted TypedListValues, level_bytes }
 */
std::pair<TypedListValues, std::vector<uint8_t> > DecryptTypedListValuesWithLevelBytes(
    const std::vector<uint8_t>& combined_blob,
    Type::type datatype,
    const std::vector<uint8_t>& key);
/**
 * Inverse of EncryptTypedListValues.
 * Parses the encrypted blob into EncryptedValue entries, decrypts each with key,
 * deserializes each element according to the provided datatype, and aggregates
 * them into a single TypedListValues.
 *
 * @param blob Concatenated encrypted elements blob (from EncryptTypedListValues)
 * @param datatype Data type of the elements (dbps::external::Type)
 * @param key Byte-array decryption key
 * @return TypedListValues containing the decrypted elements
 */
TypedListValues DecryptTypedListValues(
    const std::vector<uint8_t>& blob,
    Type::type datatype,
    const std::vector<uint8_t>& key);
} // namespace dbps::value_encryption_utils
