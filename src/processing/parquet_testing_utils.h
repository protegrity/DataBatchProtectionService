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

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <tcb/span.hpp>

#include "enum_utils.h"
#include "enums.h"
#include "../common/bytes_utils.h"
#include "../common/exceptions.h"

using namespace dbps::external;
using RawValueBytes = std::vector<uint8_t>;

inline size_t GetFixedElemSizeOrThrowForTesting(
    Type::type datatype,
    const std::optional<int>& datatype_length) {
    switch (datatype) {
        case Type::INT32:
        case Type::FLOAT:
            return 4;
        case Type::INT64:
        case Type::DOUBLE:
            return 8;
        case Type::INT96:
            return 12;
        case Type::FIXED_LEN_BYTE_ARRAY: {
            if (!datatype_length.has_value() || datatype_length.value() <= 0) {
                throw InvalidInputException("FIXED_LEN_BYTE_ARRAY requires a positive datatype_length");
            }
            return static_cast<size_t>(datatype_length.value());
        }
        case Type::BOOLEAN:
            throw InvalidInputException("BOOLEAN is bit-sized; not fixed byte-sized");
        case Type::BYTE_ARRAY:
            throw InvalidInputException("BYTE_ARRAY is variable-length; not fixed-size");
        default:
            throw InvalidInputException(
                "Invalid datatype. Only fixed-size types are supported: " + std::string(dbps::enum_utils::to_string(datatype)));
    }
}

inline std::vector<uint8_t> CombineRawBytesIntoValueBytesForTesting(
    const std::vector<RawValueBytes>& elements,
    Type::type datatype,
    const std::optional<int>& datatype_length,
    Encoding::type encoding) {
    if (encoding == Encoding::RLE_DICTIONARY) {
        throw DBPSUnsupportedException("Unsupported encoding: RLE_DICTIONARY is not supported for per-value operations");
    }
    if (encoding != Encoding::PLAIN) {
        throw DBPSUnsupportedException(
            "On CombineRawBytesIntoValueBytes, unsupported encoding: " + std::string(dbps::enum_utils::to_string(encoding)));
    }
    if (datatype == Type::BOOLEAN) {
        throw DBPSUnsupportedException("On CombineRawBytesIntoValueBytes, BOOLEAN datatype is not supported.");
    }

    if (datatype == Type::BYTE_ARRAY) {
        std::vector<uint8_t> out;
        size_t total = 0;
        for (const auto& v : elements) {
            total += 4 + v.size();
        }
        out.reserve(total);
        for (const auto& v : elements) {
            append_u32_le(out, static_cast<uint32_t>(v.size()));
            out.insert(out.end(), v.begin(), v.end());
        }
        return out;
    }

    const size_t elem_size = GetFixedElemSizeOrThrowForTesting(datatype, datatype_length);
    for (const auto& elem : elements) {
        if (elem.size() != elem_size) {
            throw InvalidInputException("Element size mismatch for fixed-size datatype");
        }
    }

    std::vector<uint8_t> out;
    out.reserve(elem_size * elements.size());
    for (const auto& v : elements) {
        out.insert(out.end(), v.begin(), v.end());
    }
    return out;
}

inline std::vector<uint8_t> BuildByteArrayValueBytesForTesting(const std::string& payload) {
    std::vector<RawValueBytes> elements;
    elements.emplace_back(payload.begin(), payload.end());
    return CombineRawBytesIntoValueBytesForTesting(
        elements, Type::BYTE_ARRAY, std::nullopt, Encoding::PLAIN);
}

inline std::vector<std::string> ParseByteArrayListValueBytesForTesting(const std::vector<uint8_t>& bytes) {
    std::vector<std::string> out;
    const uint8_t* p = bytes.data();
    const uint8_t* last = bytes.data() + bytes.size();
    while (p + 4 <= last) {
        const uint32_t len = read_u32_le(tcb::span<const uint8_t>(bytes), static_cast<size_t>(p - bytes.data()));
        p += 4;
        if (p + len > last) {
            throw InvalidInputException("Invalid BYTE_ARRAY encoding: length exceeds data bounds");
        }
        out.emplace_back(reinterpret_cast<const char*>(p), reinterpret_cast<const char*>(p + len));
        p += len;
    }
    if (p != last) {
        throw InvalidInputException("Invalid BYTE_ARRAY encoding: trailing bytes remain");
    }
    return out;
}
