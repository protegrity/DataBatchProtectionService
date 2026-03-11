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
#include <chrono>
#include <cstring>
#include <iostream>
#include <type_traits>

using namespace dbps::processing;
using namespace dbps::external;

namespace {
    int64_t ElapsedNanosecondsSince(const std::chrono::steady_clock::time_point& start) {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - start).count();
    }

    int64_t ToMicroseconds(int64_t nanoseconds) {
        return nanoseconds / 1000;
    }

    void PrintDurationLine(const char* label, int64_t nanoseconds) {
        std::cout << "  " << label << ": "
                  << ToMicroseconds(nanoseconds) << " us"
                  << " (" << nanoseconds << " ns)" << std::endl;
    }

    void PrintBasicXorBlockTimings(const char* operation, int64_t total_ns) {
        std::cout << "+++++ BasicXorEncryptor timings (microseconds + nanoseconds) +++++" << std::endl;
        PrintDurationLine(operation, total_ns);
    }

    void PrintBasicXorEncryptTypedElementsTimings(
        bool is_fixed,
        size_t num_elements,
        size_t element_size,
        int64_t encrypt_elements_loop_ns,
        int64_t get_raw_element_ns,
        int64_t xor_encrypt_ns,
        int64_t set_element_ns,
        int64_t finalize_buffer_ns,
        int64_t write_header_ns,
        int64_t total_ns) {
        std::cout << "+++++ BasicXorEncryptor EncryptTypedElements timings (microseconds + nanoseconds) +++++" << std::endl;
        std::cout << "  mode: " << (is_fixed ? "fixed" : "variable") << std::endl;
        std::cout << "  num_elements: " << num_elements << std::endl;
        std::cout << "  element_size: " << element_size << std::endl;
        PrintDurationLine("EncryptElementsLoop", encrypt_elements_loop_ns);
        PrintDurationLine("GetRawElement(aggregated)", get_raw_element_ns);
        PrintDurationLine("XorEncrypt(aggregated)", xor_encrypt_ns);
        PrintDurationLine("SetElement(aggregated)", set_element_ns);
        PrintDurationLine(
            "LoopResidual(iterator+other)",
            encrypt_elements_loop_ns - get_raw_element_ns - xor_encrypt_ns - set_element_ns);
        PrintDurationLine("FinalizeBuffer", finalize_buffer_ns);
        PrintDurationLine("WriteHeader", write_header_ns);
        PrintDurationLine("EncryptTypedElements(total)", total_ns);
    }

    void PrintBasicXorEncryptValueListTimings(int64_t visit_dispatch_ns, int64_t total_ns) {
        std::cout << "+++++ BasicXorEncryptor EncryptValueList timings (microseconds + nanoseconds) +++++" << std::endl;
        PrintDurationLine("VariantVisitAndEncrypt", visit_dispatch_ns);
        PrintDurationLine("EncryptValueList(total)", total_ns);
    }

    void PrintBasicXorDecryptValueListTimings(
        bool is_fixed,
        size_t num_elements,
        int64_t read_header_ns,
        int64_t setup_buffer_ns,
        int64_t decrypt_elements_ns,
        int64_t total_ns) {
        std::cout << "+++++ BasicXorEncryptor DecryptValueList timings (microseconds + nanoseconds) +++++" << std::endl;
        std::cout << "  mode: " << (is_fixed ? "fixed" : "variable") << std::endl;
        std::cout << "  num_elements: " << num_elements << std::endl;
        PrintDurationLine("ReadHeader", read_header_ns);
        PrintDurationLine("SetupEncryptedBuffer", setup_buffer_ns);
        PrintDurationLine("DecryptElements", decrypt_elements_ns);
        PrintDurationLine("DecryptValueList(total)", total_ns);
    }
}

// ---------------------------------------------------------------------------
// Functions for encrypting and decrypting byte arrays.
// ---------------------------------------------------------------------------

std::vector<uint8_t> BasicXorEncryptor::XorEncrypt(tcb::span<const uint8_t> data) {
    if (data.empty()) {
        return {};
    }
    size_t key_hash = key_id_hash_;
    std::vector<uint8_t> out(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        out[i] = data[i] ^ (key_hash & 0xFF);
        key_hash = (key_hash << 1) | (key_hash >> 31);
    }
    return out;
}

std::vector<uint8_t> BasicXorEncryptor::XorDecrypt(tcb::span<const uint8_t> data) {
    return XorEncrypt(data);
}

// ---------------------------------------------------------------------------
// Block encryption
// ---------------------------------------------------------------------------

std::vector<uint8_t> BasicXorEncryptor::EncryptBlock(tcb::span<const uint8_t> data) {
    auto start = std::chrono::steady_clock::now();
    auto out = XorEncrypt(data, key_id_);
    PrintBasicXorBlockTimings("EncryptBlock", ElapsedNanosecondsSince(start));
    return out;
}

std::vector<uint8_t> BasicXorEncryptor::DecryptBlock(tcb::span<const uint8_t> data) {
    auto start = std::chrono::steady_clock::now();
    auto out = XorDecrypt(data, key_id_);
    PrintBasicXorBlockTimings("DecryptBlock", ElapsedNanosecondsSince(start));
    return out;
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
    const TypedBuffer& input_buffer) {
    auto total_start = std::chrono::steady_clock::now();
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
    int64_t encrypt_elements_loop_ns = 0;
    int64_t get_raw_element_ns = 0;
    int64_t xor_encrypt_ns = 0;
    int64_t set_element_ns = 0;
    int64_t finalize_buffer_ns = 0;

    // Encrypt fixed-size elements
    if constexpr (is_fixed) {
        element_size = input_buffer.GetElementSize();
        TypedBufferRawBytesFixedSized output_buffer{
            num_elements, prefix_length, RawBytesFixedSizedCodec{element_size}};
        auto stage_start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < num_elements; ++i) {
            auto op_start = std::chrono::steady_clock::now();
            auto raw_bytes = input_buffer.GetRawElement(i);
            get_raw_element_ns += ElapsedNanosecondsSince(op_start);
            op_start = std::chrono::steady_clock::now();
            auto encrypted = XorEncrypt(raw_bytes, key_id);
            xor_encrypt_ns += ElapsedNanosecondsSince(op_start);
            op_start = std::chrono::steady_clock::now();
            output_buffer.SetElement(i, tcb::span<const uint8_t>(encrypted));
            set_element_ns += ElapsedNanosecondsSince(op_start);
        }
        encrypt_elements_loop_ns = ElapsedNanosecondsSince(stage_start);
        stage_start = std::chrono::steady_clock::now();
        final_buffer = output_buffer.FinalizeAndTakeBuffer();
        finalize_buffer_ns = ElapsedNanosecondsSince(stage_start);
    }
    
    // Encrypt variable-size elements
    else {
        auto reserved_bytes_hint = input_buffer.GetRawBufferSize();
        TypedBufferRawBytesVariableSized output_buffer{
            num_elements, reserved_bytes_hint, true, prefix_length};

        auto stage_start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < num_elements; ++i) {

            auto op_start = std::chrono::steady_clock::now();
            auto raw_bytes = input_buffer.GetRawElement(i);
            get_raw_element_ns += ElapsedNanosecondsSince(op_start);

            op_start = std::chrono::steady_clock::now();
            auto encrypted = XorEncrypt(raw_bytes, key_id);
            xor_encrypt_ns += ElapsedNanosecondsSince(op_start);
            
            op_start = std::chrono::steady_clock::now();
            output_buffer.SetElement(i, tcb::span<const uint8_t>(encrypted));
            set_element_ns += ElapsedNanosecondsSince(op_start);
        }
        encrypt_elements_loop_ns = ElapsedNanosecondsSince(stage_start);
        stage_start = std::chrono::steady_clock::now();
        final_buffer = output_buffer.FinalizeAndTakeBuffer();
        finalize_buffer_ns = ElapsedNanosecondsSince(stage_start);
    }

    // Write the header to the final buffer and return it.
    auto header_start = std::chrono::steady_clock::now();
    WriteHeader(final_buffer, {is_fixed,
        static_cast<uint32_t>(num_elements),
        static_cast<uint32_t>(element_size)});
    auto write_header_ns = ElapsedNanosecondsSince(header_start);

    PrintBasicXorEncryptTypedElementsTimings(
        is_fixed,
        num_elements,
        element_size,
        encrypt_elements_loop_ns,
        get_raw_element_ns,
        xor_encrypt_ns,
        set_element_ns,
        finalize_buffer_ns,
        write_header_ns,
        ElapsedNanosecondsSince(total_start));
    return final_buffer;
}

std::vector<uint8_t> BasicXorEncryptor::EncryptValueList(
    const TypedValuesBuffer& typed_buffer) {
    auto total_start = std::chrono::steady_clock::now();

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
    auto visit_start = std::chrono::steady_clock::now();
    auto encrypted = std::visit([&](const auto& input_buffer) {
        return EncryptTypedElements(input_buffer, key_id_);
    }, typed_buffer);
    auto visit_dispatch_ns = ElapsedNanosecondsSince(visit_start);
    PrintBasicXorEncryptValueListTimings(visit_dispatch_ns, ElapsedNanosecondsSince(total_start));
    return encrypted;
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
    const TypedBufferRawBytesFixedSized& encrypted_buffer, TypedBuffer output_buffer) {
    size_t output_index = 0;
    for (const auto raw_bytes : encrypted_buffer.raw_elements()) {
        auto decrypted_bytes = XorDecrypt(raw_bytes);
        output_buffer.SetRawElement(output_index, tcb::span<const uint8_t>(decrypted_bytes));
        output_index++;
    }
    return output_buffer;
}

TypedValuesBuffer BasicXorEncryptor::DecryptValueList(
    tcb::span<const uint8_t> encrypted_bytes) {
    auto total_start = std::chrono::steady_clock::now();

    auto stage_start = std::chrono::steady_clock::now();
    auto header = ReadHeader(encrypted_bytes);
    auto read_header_ns = ElapsedNanosecondsSince(stage_start);
    auto num_elements = static_cast<size_t>(header.num_elements);

    // Decrypt fixed-size elements
    if (header.is_fixed) {
        stage_start = std::chrono::steady_clock::now();

        // Create a fixed-sized byte buffer for reading the encrypted elements.
        TypedBufferRawBytesFixedSized encrypted_buffer{
            encrypted_bytes, kFixedHeaderLength, RawBytesFixedSizedCodec{header.element_size}};
        auto setup_buffer_ns = ElapsedNanosecondsSince(stage_start);

        // Populate a typed buffer with the decrypted elements in the corresponding type.
        stage_start = std::chrono::steady_clock::now();
        switch (datatype_) {
            case Type::INT32:
            {
                auto out = DecryptFixedSizedElementsIntoTypedBuffer(
                    encrypted_buffer, key_id_, TypedBufferI32{num_elements});
                PrintBasicXorDecryptValueListTimings(
                    true, num_elements, read_header_ns, setup_buffer_ns,
                    ElapsedNanosecondsSince(stage_start), ElapsedNanosecondsSince(total_start));
                return out;
            }
            case Type::INT64:
            {
                auto out = DecryptFixedSizedElementsIntoTypedBuffer(
                    encrypted_buffer, key_id_, TypedBufferI64{num_elements});
                PrintBasicXorDecryptValueListTimings(
                    true, num_elements, read_header_ns, setup_buffer_ns,
                    ElapsedNanosecondsSince(stage_start), ElapsedNanosecondsSince(total_start));
                return out;
            }
            case Type::INT96:
            {
                auto out = DecryptFixedSizedElementsIntoTypedBuffer(
                    encrypted_buffer, key_id_, TypedBufferInt96{num_elements});
                PrintBasicXorDecryptValueListTimings(
                    true, num_elements, read_header_ns, setup_buffer_ns,
                    ElapsedNanosecondsSince(stage_start), ElapsedNanosecondsSince(total_start));
                return out;
            }
            case Type::FLOAT:
            {
                auto out = DecryptFixedSizedElementsIntoTypedBuffer(
                    encrypted_buffer, key_id_, TypedBufferFloat{num_elements});
                PrintBasicXorDecryptValueListTimings(
                    true, num_elements, read_header_ns, setup_buffer_ns,
                    ElapsedNanosecondsSince(stage_start), ElapsedNanosecondsSince(total_start));
                return out;
            }
            case Type::DOUBLE:
            {
                auto out = DecryptFixedSizedElementsIntoTypedBuffer(
                    encrypted_buffer, key_id_, TypedBufferDouble{num_elements});
                PrintBasicXorDecryptValueListTimings(
                    true, num_elements, read_header_ns, setup_buffer_ns,
                    ElapsedNanosecondsSince(stage_start), ElapsedNanosecondsSince(total_start));
                return out;
            }
            case Type::FIXED_LEN_BYTE_ARRAY:
            {
                auto out = DecryptFixedSizedElementsIntoTypedBuffer(
                    encrypted_buffer, key_id_,
                    TypedBufferRawBytesFixedSized{num_elements, 0, RawBytesFixedSizedCodec{header.element_size}});
                PrintBasicXorDecryptValueListTimings(
                    true, num_elements, read_header_ns, setup_buffer_ns,
                    ElapsedNanosecondsSince(stage_start), ElapsedNanosecondsSince(total_start));
                return out;
            }
            default:
                throw InvalidInputException(
                    std::string("DecryptValueList: unsupported fixed-size datatype: ")
                    + std::string(dbps::enum_utils::to_string(datatype_)));
        }
    } 
    
    // Decrypt variable-size elements
    else {
        stage_start = std::chrono::steady_clock::now();
        // Create a variable-sized byte buffer for reading the encrypted elements.
        TypedBufferRawBytesVariableSized encrypted_buffer{ encrypted_bytes, kVariableHeaderLength};
        auto setup_buffer_ns = ElapsedNanosecondsSince(stage_start);

        switch (datatype_) {
            // Create a BYTE-ARRAY typed buffer for storing the decrypted elements.
            case Type::BYTE_ARRAY: {
                auto reserved_bytes_hint = encrypted_buffer.GetRawBufferSize();
                TypedBufferRawBytesVariableSized output_buffer{num_elements, reserved_bytes_hint, true};
                size_t output_index = 0;
                stage_start = std::chrono::steady_clock::now();
                for (const auto element : encrypted_buffer) {
                    auto decrypted_bytes = XorDecrypt(element);
                    output_buffer.SetElement(output_index, tcb::span<const uint8_t>(decrypted_bytes));
                    output_index++;
                }
                auto decrypt_elements_ns = ElapsedNanosecondsSince(stage_start);
                PrintBasicXorDecryptValueListTimings(
                    false, num_elements, read_header_ns, setup_buffer_ns,
                    decrypt_elements_ns, ElapsedNanosecondsSince(total_start));
                return output_buffer;
            }
            default:
                throw InvalidInputException(
                    std::string("DecryptValueList: unsupported variable-size datatype: ")
                    + std::string(dbps::enum_utils::to_string(datatype_)));
        }
    }
}
