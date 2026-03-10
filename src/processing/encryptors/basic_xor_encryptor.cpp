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

std::vector<uint8_t> BasicXorEncryptor::XorEncrypt(tcb::span<const uint8_t> data, const std::string& key_id) {
    if (data.empty()) {
        return {};
    }
    if (key_id.empty()) {
        throw std::invalid_argument("XorEncrypt: key must not be empty for non-empty data");
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

std::vector<uint8_t> BasicXorEncryptor::XorDecrypt(tcb::span<const uint8_t> data, const std::string& key_id) {
    return XorEncrypt(data, key_id);
}

// ---------------------------------------------------------------------------
// Block encryption
// ---------------------------------------------------------------------------

std::vector<uint8_t> BasicXorEncryptor::EncryptBlock(tcb::span<const uint8_t> data) {
    return XorEncrypt(data, key_id_);
}

std::vector<uint8_t> BasicXorEncryptor::DecryptBlock(tcb::span<const uint8_t> data) {
    return XorDecrypt(data, key_id_);
}

// ---------------------------------------------------------------------------
// Value-level encryption  (TypedValuesBuffer in -> bytes out)
//
// Output layout:
//   Fixed:    [0x01][uint32 count][uint32 elem_size] <contiguous encrypted elements>
//   Variable: [0x00][uint32 count]                   <length-prefixed encrypted elements>
//
// NOTE ON TYPE-SPECIFIC ENCRYPTION:
//
// While this version of EncryptValueList is aware of types, the implementation ignores the type
// of the TypeValuesBuffer. It encrypts each element by interpreting the elements a plain bytes,
// not utilizing the specific type of the buffer elements (INT32, INT64, etc.).
// 
// A more sophisticated implementation could take advantage of the specific element type
// to call type-specific encryption functions, if the underlying library supports them.
//
// Further, a context-aware encryptor can additionally take advantage of the app_context, 
// user_id, and column_name to further customize the encryption process, refined access control, etc.
//
// For example, a type-specific encryption per element could look like:
//   assert(input_buffer.IsTypedBufferI32());
//   size_t i = 0;
//   for (const int32_t element : input_buffer) {    // e.g. int32_t for TypedBufferI32
//       auto encrypted = library.EncryptInt32(element, key_id);
//       output_buffer.SetElement(i++, encrypted);
//   }
//
// ---------------------------------------------------------------------------

template <typename TypedBuffer>
std::vector<uint8_t> BasicXorEncryptor::EncryptTypedElements(
    const TypedBuffer& input_buffer, const std::string& key_id) {
    constexpr bool is_fixed = TypedBuffer::is_fixed_sized;
    constexpr size_t prefix_length = is_fixed ? kFixedHeaderLength : kVariableHeaderLength;
    const size_t num_elements = input_buffer.GetNumElements();

    // If there are no elements, return an empty buffer with the header.
    if (num_elements == 0) {
        std::vector<uint8_t> result(prefix_length);
        WriteHeader(result, {is_fixed, 0, 0});
        return result;
    }

    // Encrypt the elements by traversing the typed input buffer and encrypt each element separately:
    // - Create an output raw-bytes buffer to capture the encrypted elements as bytes.
    // - For each element: read its raw bytes, encrypt them, write into the output buffer.
    // - Finalize the output buffer into a contiguous byte vector.

    std::vector<uint8_t> final_buffer;
    size_t element_size = 0;

    // Encrypt fixed-size elements
    if constexpr (is_fixed) {
        element_size = input_buffer.GetElementSize();
        TypedBufferRawBytesFixedSized output_buffer{
            num_elements, prefix_length, RawBytesFixedSizedCodec{element_size}};
        size_t output_index = 0;
        for (const auto raw_bytes : input_buffer.raw_elements()) {
            auto encrypted = XorEncrypt(raw_bytes, key_id);
            output_buffer.SetElement(output_index, tcb::span<const uint8_t>(encrypted));
            output_index++;
        }
        final_buffer = output_buffer.FinalizeAndTakeBuffer();
    }
    
    // Encrypt variable-size elements
    else {
        auto reserved_bytes_hint = input_buffer.GetRawBufferSize();
        TypedBufferRawBytesVariableSized output_buffer{
            num_elements, reserved_bytes_hint, true, prefix_length};
        size_t output_index = 0;
        for (const auto raw_bytes : input_buffer.raw_elements()) {
            auto encrypted = XorEncrypt(raw_bytes, key_id);
            output_buffer.SetElement(output_index, tcb::span<const uint8_t>(encrypted));
            output_index++;
        }
        final_buffer = output_buffer.FinalizeAndTakeBuffer();
    }

    // Write the header to the final buffer and return it.
    WriteHeader(final_buffer, {is_fixed,
        static_cast<uint32_t>(num_elements),
        static_cast<uint32_t>(element_size)});
    return final_buffer;
}

std::vector<uint8_t> BasicXorEncryptor::EncryptValueList(
    const TypedValuesBuffer& typed_buffer) {

    // Printable context string for logging
    // std::string context_str = std::string("Context parameters:")
    //    + "\n  column_name: " + column_name_
    //    + "\n  user_id: " + user_id_
    //    + "\n  key_id: " + key_id_
    //    + "\n  application_context: " + application_context_
    //    + "\n  datatype: " + std::string(dbps::enum_utils::to_string(datatype_));

    // Printable typed buffer string for logging -- Commented out by default to avoid performance impact.
    // std::string typed_buffer_str = PrintableTypedValuesBuffer(typed_buffer);
        
    // std::visit extracts the concrete buffer type from the TypedValuesBuffer variant
    // and forwards it to EncryptTypedElements, which handles all buffer types generically.
    return std::visit([&](const auto& input_buffer) {
        return EncryptTypedElements(input_buffer, key_id_);
    }, typed_buffer);
}

// ---------------------------------------------------------------------------
// Value-level decryption  (bytes in -> TypedValuesBuffer out)
//
// Parses the header, then creates a correctly-typed buffer matching datatype_ (INT32, INT64, etc.).
// Calls the byte-array decryptor to decrypt the elements into the typed buffer. 
// ---------------------------------------------------------------------------

// Helper function to decrypt fixed-size elements into the output TypedBuffer type.
template <typename TypedBuffer>
TypedBuffer BasicXorEncryptor::DecryptFixedSizedElementsIntoTypedBuffer(
    const TypedBufferRawBytesFixedSized& encrypted_buffer, const std::string& key_id, TypedBuffer output_buffer) {
    size_t output_index = 0;
    for (const auto raw_bytes : encrypted_buffer.raw_elements()) {
        auto decrypted_bytes = XorDecrypt(raw_bytes, key_id);
        output_buffer.SetRawElement(output_index, tcb::span<const uint8_t>(decrypted_bytes));
        output_index++;
    }
    return output_buffer;
}

TypedValuesBuffer BasicXorEncryptor::DecryptValueList(
    tcb::span<const uint8_t> encrypted_bytes) {

    auto header = ReadHeader(encrypted_bytes);
    auto num_elements = static_cast<size_t>(header.num_elements);

    // Decrypt fixed-size elements
    if (header.is_fixed) {

        // Create a fixed-sized byte buffer for reading the encrypted elements.
        TypedBufferRawBytesFixedSized encrypted_buffer{
            encrypted_bytes, kFixedHeaderLength, RawBytesFixedSizedCodec{header.element_size}};

        // Populate a typed buffer with the decrypted elements in the corresponding type.
        switch (datatype_) {
            case Type::INT32:
                return DecryptFixedSizedElementsIntoTypedBuffer(
                    encrypted_buffer, key_id_, TypedBufferI32{num_elements});
            case Type::INT64:
                return DecryptFixedSizedElementsIntoTypedBuffer(
                    encrypted_buffer, key_id_, TypedBufferI64{num_elements});
            case Type::INT96:
                return DecryptFixedSizedElementsIntoTypedBuffer(
                    encrypted_buffer, key_id_, TypedBufferInt96{num_elements});
            case Type::FLOAT:
                return DecryptFixedSizedElementsIntoTypedBuffer(
                    encrypted_buffer, key_id_, TypedBufferFloat{num_elements});
            case Type::DOUBLE:
                return DecryptFixedSizedElementsIntoTypedBuffer(
                    encrypted_buffer, key_id_, TypedBufferDouble{num_elements});
            case Type::FIXED_LEN_BYTE_ARRAY:
                return DecryptFixedSizedElementsIntoTypedBuffer(
                    encrypted_buffer, key_id_,
                    TypedBufferRawBytesFixedSized{num_elements, 0, RawBytesFixedSizedCodec{header.element_size}});
            default:
                throw InvalidInputException(
                    std::string("DecryptValueList: unsupported fixed-size datatype: ")
                    + std::string(dbps::enum_utils::to_string(datatype_)));
        }
    } 
    
    // Decrypt variable-size elements
    else {
        // Create a variable-sized byte buffer for reading the encrypted elements.
        TypedBufferRawBytesVariableSized encrypted_buffer{ encrypted_bytes, kVariableHeaderLength};

        switch (datatype_) {
            // Create a BYTE-ARRAY typed buffer for storing the decrypted elements.
            case Type::BYTE_ARRAY: {
                auto reserved_bytes_hint = encrypted_buffer.GetRawBufferSize();
                TypedBufferRawBytesVariableSized output_buffer{num_elements, reserved_bytes_hint, true};
                size_t output_index = 0;
                for (const auto element : encrypted_buffer) {
                    auto decrypted_bytes = XorDecrypt(element, key_id_);
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
