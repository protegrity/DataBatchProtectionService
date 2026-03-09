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

#include "basic_xor_encryptor.h"
#include "encryptor_utils.h"
#include "../../common/exceptions.h"
#include "../../common/enum_utils.h"
#include <cstring>
#include <functional>
#include <iostream>
#include <type_traits>

using namespace dbps::processing;
using namespace dbps::external;

// ---------------------------------------------------------------------------
// Functions for encrypting and decrypting byte arrays.
// ---------------------------------------------------------------------------

static std::vector<uint8_t> EncryptByteArray(tcb::span<const uint8_t> data, const std::string& key_id) {
    if (data.empty()) {
        return {};
    }
    if (key_id.empty()) {
        throw std::invalid_argument("EncryptByteArray: key must not be empty for non-empty data");
    }
    std::vector<uint8_t> out(data.size());
    std::hash<std::string> hasher;
    size_t key_hash = hasher(key_id);
    for (size_t i = 0; i < data.size(); ++i) {
        out[i] = data[i] ^ (key_hash & 0xFF);
        key_hash = (key_hash << 1) | (key_hash >> 31);
    }
    return out;
}

static std::vector<uint8_t> DecryptByteArray(tcb::span<const uint8_t> data, const std::string& key_id) {
    return EncryptByteArray(data, key_id);
}

// ---------------------------------------------------------------------------
// Block encryption
// ---------------------------------------------------------------------------

std::vector<uint8_t> BasicXorEncryptor::EncryptBlock(tcb::span<const uint8_t> data) {
    return EncryptByteArray(data, key_id_);
}

std::vector<uint8_t> BasicXorEncryptor::DecryptBlock(tcb::span<const uint8_t> data) {
    return DecryptByteArray(data, key_id_);
}

// ---------------------------------------------------------------------------
// Value-level encryption  (TypedValuesBuffer in -> bytes out)
//
// Output layout:
//   Fixed:    [0x01][uint32 count][uint32 elem_size] <contiguous encrypted elements>
//   Variable: [0x00][uint32 count]                   <length-prefixed encrypted elements>
//
// ---------------------------------------------------------------------------

std::vector<uint8_t> BasicXorEncryptor::EncryptValueList(
    const TypedValuesBuffer& typed_buffer) {

    std::cout << "EncryptValueList context: column=" << column_name_
              << " user=" << user_id_ << " key=" << key_id_
              << " datatype=" << dbps::enum_utils::to_string(datatype_) << std::endl;

    return std::visit([&](const auto& input_buffer) -> std::vector<uint8_t> {
        using BufferType = std::decay_t<decltype(input_buffer)>;
        constexpr bool is_fixed = BufferType::is_fixed_sized;
        const size_t num_elements = input_buffer.GetNumElements();
        constexpr size_t prefix_length = is_fixed ? kFixedHeaderLength : kVariableHeaderLength;

        // Empty buffer, return empty vector with header.
        if (num_elements == 0) {
            std::vector<uint8_t> result(prefix_length);
            WriteHeader(result, {is_fixed, 0, 0});
            return result;
        }

        auto encrypt_into = [&](auto& output_buffer) -> std::vector<uint8_t> {
            size_t output_index = 0;
            for (const auto raw_bytes : input_buffer.raw_elements()) {
                auto encrypted = EncryptByteArray(raw_bytes, key_id_);
                output_buffer.SetElement(output_index, tcb::span<const uint8_t>(encrypted));
                output_index++;
            }
            return output_buffer.FinalizeAndTakeBuffer();
        };

        std::vector<uint8_t> final_buffer;
        size_t element_size = 0;
        if constexpr (is_fixed) {
            element_size = input_buffer.GetElementSize();
            TypedBufferRawBytesFixedSized output_buffer{
                num_elements, prefix_length, RawBytesFixedSizedCodec{element_size}};
            final_buffer = encrypt_into(output_buffer);
        } else {
            auto reserved_bytes_hint = input_buffer.GetRawBufferSize();
            TypedBufferRawBytesVariableSized output_buffer{
                num_elements, reserved_bytes_hint, true, prefix_length};
            final_buffer = encrypt_into(output_buffer);
        }
        WriteHeader(final_buffer, {is_fixed,
            static_cast<uint32_t>(num_elements),
            static_cast<uint32_t>(element_size)});
        return final_buffer;

    }, typed_buffer);
}

// ---------------------------------------------------------------------------
// Value-level decryption  (bytes in -> TypedValuesBuffer out)
//
// Parses the header, then wraps the full span (with prefix_size) as a
// TypedBufferRawBytes... read buffer so the buffer skips the header
// automatically.  Output is the correctly-typed buffer matching datatype_.
// ---------------------------------------------------------------------------

// Helper function to decrypt fixed-size buffer into a specific output TypedBuffer type.
template <typename OutputBuffer>
static OutputBuffer DecryptFixedIntoBuffer(
    const TypedBufferRawBytesFixedSized& encrypted_buffer,
    const std::string& key_id,
    OutputBuffer output_buffer) {
    size_t output_index = 0;
    for (const auto raw_bytes : encrypted_buffer.raw_elements()) {
        auto decrypted_bytes = DecryptByteArray(raw_bytes, key_id);
        output_buffer.SetRawElement(output_index, tcb::span<const uint8_t>(decrypted_bytes));
        output_index++;
    }
    return output_buffer;
}

TypedValuesBuffer BasicXorEncryptor::DecryptValueList(
    tcb::span<const uint8_t> encrypted_bytes) {

    auto header = ReadHeader(encrypted_bytes);
    auto num_elements = static_cast<size_t>(header.num_elements);

    if (header.is_fixed) {
        TypedBufferRawBytesFixedSized encrypted_buffer{
            encrypted_bytes, kFixedHeaderLength,
            RawBytesFixedSizedCodec{header.element_size}};

        // TODO: This is leaking Parquet-specific types into the encryptor, which should be agnostic of Parquet.
        // This is needed because on the returned bytes we are not saving a type information.
        // We could annotate the generating bytes by simply updating the 1st byte of the header to indicate the type.
        switch (datatype_) {
            case Type::INT32:
                return DecryptFixedIntoBuffer(encrypted_buffer, key_id_, TypedBufferI32{num_elements});
            case Type::INT64:
                return DecryptFixedIntoBuffer(encrypted_buffer, key_id_, TypedBufferI64{num_elements});
            case Type::INT96:
                return DecryptFixedIntoBuffer(encrypted_buffer, key_id_, TypedBufferInt96{num_elements});
            case Type::FLOAT:
                return DecryptFixedIntoBuffer(encrypted_buffer, key_id_, TypedBufferFloat{num_elements});
            case Type::DOUBLE:
                return DecryptFixedIntoBuffer(encrypted_buffer, key_id_, TypedBufferDouble{num_elements});
            case Type::FIXED_LEN_BYTE_ARRAY: {
                TypedBufferRawBytesFixedSized output_buffer{
                    num_elements, 0, RawBytesFixedSizedCodec{header.element_size}};
                size_t output_index = 0;
                for (const auto element : encrypted_buffer) {
                    auto decrypted_bytes = DecryptByteArray(element, key_id_);
                    output_buffer.SetElement(output_index, tcb::span<const uint8_t>(decrypted_bytes));
                    output_index++;
                }
                return output_buffer;
            }
            default:
                throw InvalidInputException(
                    std::string("DecryptValueList: unsupported fixed-size datatype: ")
                    + std::string(dbps::enum_utils::to_string(datatype_)));
        }
    } else {
        TypedBufferRawBytesVariableSized encrypted_buffer{
            encrypted_bytes, kVariableHeaderLength};

        switch (datatype_) {
            case Type::BYTE_ARRAY: {
                auto reserved_bytes_hint = encrypted_buffer.GetRawBufferSize();
                TypedBufferRawBytesVariableSized output_buffer{num_elements, reserved_bytes_hint, true};
                size_t output_index = 0;
                for (const auto element : encrypted_buffer) {
                    auto decrypted_bytes = DecryptByteArray(element, key_id_);
                    output_buffer.SetElement(output_index, tcb::span<const uint8_t>(decrypted_bytes));
                    output_index++;
                }
                return output_buffer;
            }
            default:
                throw InvalidInputException(
                    std::string("DecryptValueList: unsupported variable-size datatype: ")
                    + std::string(dbps::enum_utils::to_string(datatype_)));
        }
    }
}
