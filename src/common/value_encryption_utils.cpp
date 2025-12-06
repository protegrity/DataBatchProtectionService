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

#include "value_encryption_utils.h"

#include <stdexcept>
#include <limits>
#include <cstring>
#include <string>
#include <array>
#include <variant>
#include <type_traits>
#include "bytes_utils.h"

namespace dbps::value_encryption_utils {

std::vector<uint8_t> ConcatenateEncryptedValues(const std::vector<EncryptedValue>& values) {
    if (values.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        throw InvalidInputException("Too many elements to serialize into uint32 count");
    }

    // Precompute capacity: 4 bytes for count + for each element (4 bytes size + payload)
    size_t total_capacity = 4;
    for (size_t i = 0; i < values.size(); ++i) {
        const EncryptedValue& ev = values[i];
        const size_t payload_size = ev.size();
        if (payload_size > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
            throw InvalidInputException("Element size exceeds uint32 capacity");
        }
        total_capacity += 4 + payload_size;
    }

    std::vector<uint8_t> out;
    out.reserve(total_capacity);

    append_u32_le(out, static_cast<uint32_t>(values.size()));

    for (size_t i = 0; i < values.size(); ++i) {
        const EncryptedValue& ev = values[i];
        append_u32_le(out, static_cast<uint32_t>(ev.size()));
        // Append the entire payload (ciphertext)
        out.insert(out.end(), ev.begin(), ev.end());
    }

    return out;
}

std::vector<EncryptedValue> ParseConcatenatedEncryptedValues(const std::vector<uint8_t>& blob) {
    size_t offset = 0;
    if (blob.size() < 4) {
        throw InvalidInputException("Malformed input: missing element count");
    }
    uint32_t count = read_u32_le(blob, offset);
    offset += 4;

    std::vector<EncryptedValue> result;
    result.reserve(static_cast<size_t>(count));

    for (uint32_t i = 0; i < count; ++i) {
        if (blob.size() - offset < 4) {
            throw InvalidInputException("Malformed input: truncated size field");
        }
        uint32_t sz = read_u32_le(blob, offset);
        offset += 4;

        if (blob.size() - offset < static_cast<size_t>(sz)) {
            throw InvalidInputException("Malformed input: truncated payload bytes");
        }

        EncryptedValue ev;
        ev.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                  blob.begin() + static_cast<std::ptrdiff_t>(offset + sz));
        offset += static_cast<size_t>(sz);
        result.push_back(std::move(ev));
    }

    // ensure no trailing bytes remain after parsing
    if (offset != blob.size()) {
        throw InvalidInputException("Malformed input: trailing bytes after parsing EncryptedValue entries");
    }
    return result;
}

std::vector<EncryptedValue> EncryptTypedListValues(
    const TypedListValues& elements,
    const std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)>& fn_encrypt_byte_array) {
    std::vector<RawValueBytes> raw_values = BuildRawBytesFromTypedListValues(elements);
    std::vector<EncryptedValue> encrypted_elements;
    encrypted_elements.reserve(raw_values.size());
    
    for (size_t i = 0; i < raw_values.size(); ++i) {
        const RawValueBytes& raw = raw_values[i];
        std::vector<uint8_t> payload = fn_encrypt_byte_array(raw);
        encrypted_elements.push_back(std::move(payload));
    }
    return encrypted_elements;
}

TypedListValues DecryptTypedListValues(
    const std::vector<EncryptedValue>& encrypted_values,
    Type::type datatype,
    const std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)>& fn_decrypt_byte_array) {

    // 1) Decrypt each element into its raw bytes via callback
    std::vector<RawValueBytes> decrypted_values;
    decrypted_values.reserve(encrypted_values.size());
    for (size_t i = 0; i < encrypted_values.size(); ++i) {
        const EncryptedValue& ev = encrypted_values[i];
        RawValueBytes decrypted = fn_decrypt_byte_array(ev);
        decrypted_values.push_back(std::move(decrypted));
    }

    // 2) Convert all decrypted bytes to a TypedListValues according to datatype
    TypedListValues result = BuildTypedListFromRawBytes(datatype, decrypted_values);
    return result;
}

} // namespace dbps::value_encryption_utils
