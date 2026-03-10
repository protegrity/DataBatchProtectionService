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
#include <optional>
#include "bytes_utils.h"

namespace dbps::value_encryption_utils {

std::vector<uint8_t> ConcatenateEncryptedValues(
    const std::vector<EncryptedValue>& values,
    const std::optional<size_t>& fixed_element_size) {
    if (values.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        throw InvalidInputException("Too many elements to serialize into uint32 count");
    }

    const bool is_variable = !fixed_element_size.has_value();
    size_t total_capacity = 1 + 4;

    if (!is_variable) {
        const size_t elem_size = fixed_element_size.value();
        if (elem_size > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
            throw InvalidInputException("Element size exceeds uint32 capacity");
        }
        total_capacity += 4;
        for (size_t i = 0; i < values.size(); ++i) {
            if (values[i].size() != elem_size) {
                throw InvalidInputException("Element size does not match fixed_element_size");
            }
        }
        total_capacity += elem_size * values.size();
    } else {
        for (size_t i = 0; i < values.size(); ++i) {
            const EncryptedValue& ev = values[i];
            const size_t payload_size = ev.size();
            if (payload_size > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
                throw InvalidInputException("Element size exceeds uint32 capacity");
            }
            total_capacity += 4 + payload_size;
        }
    }

    std::vector<uint8_t> out(total_capacity);
    size_t offset = 0;

    out[offset++] = is_variable ? 1 : 0;

    auto write_u32_le = [&](uint32_t v) {
        out[offset + 0] = static_cast<uint8_t>(v & 0xFF);
        out[offset + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
        out[offset + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        out[offset + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
        offset += 4;
    };

    write_u32_le(static_cast<uint32_t>(values.size()));

    if (!is_variable) {
        const uint32_t elem_size = static_cast<uint32_t>(fixed_element_size.value());
        write_u32_le(elem_size);
        for (size_t i = 0; i < values.size(); ++i) {
            const EncryptedValue& ev = values[i];
            if (elem_size > 0) {
                std::memcpy(out.data() + offset, ev.data(), elem_size);
                offset += elem_size;
            }
        }
    } else {
        for (size_t i = 0; i < values.size(); ++i) {
            const EncryptedValue& ev = values[i];
            write_u32_le(static_cast<uint32_t>(ev.size()));
            if (!ev.empty()) {
                std::memcpy(out.data() + offset, ev.data(), ev.size());
                offset += ev.size();
            }
        }
    }

    return out;
}

std::vector<EncryptedValue> ParseConcatenatedEncryptedValues(const std::vector<uint8_t>& blob) {
    size_t offset = 0;
    if (blob.size() < 1 + 4) {
        throw InvalidInputException("Malformed input: missing header");
    }
    const bool is_variable = (blob[offset++] != 0);
    uint32_t count = read_u32_le(blob, offset);
    offset += 4;

    std::vector<EncryptedValue> result;
    result.reserve(static_cast<size_t>(count));

    if (!is_variable) {
        if (blob.size() - offset < 4) {
            throw InvalidInputException("Malformed input: missing fixed element size");
        }
        uint32_t elem_size = read_u32_le(blob, offset);
        offset += 4;
        const size_t required = static_cast<size_t>(elem_size) * static_cast<size_t>(count);
        if (blob.size() - offset < required) {
            throw InvalidInputException("Malformed input: truncated fixed-length payload bytes");
        }
        for (uint32_t i = 0; i < count; ++i) {
            EncryptedValue ev;
            ev.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                      blob.begin() + static_cast<std::ptrdiff_t>(offset + elem_size));
            offset += static_cast<size_t>(elem_size);
            result.push_back(std::move(ev));
        }
    } else {
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
