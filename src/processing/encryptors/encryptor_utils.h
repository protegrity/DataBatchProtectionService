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
#include <tcb/span.hpp>
#include "../../common/bytes_utils.h"
#include "../../common/exceptions.h"

namespace dbps::processing {

// Wire-format prefix tags.
inline constexpr uint8_t kFixedSizeTag = 0x01;
inline constexpr uint8_t kVariableSizeTag = 0x00;
inline constexpr size_t kTagLength = 1;
inline constexpr size_t kSizeTLength = 4;

// Header sizes in bytes.
//   Fixed:    [1-byte tag] [uint32 element_count] [uint32 element_size]
//   Variable: [1-byte tag] [uint32 element_count]
inline constexpr size_t kFixedHeaderLength = kTagLength + kSizeTLength + kSizeTLength;
inline constexpr size_t kVariableHeaderLength = kTagLength + kSizeTLength;

struct EncryptedValueHeader {
    bool is_fixed;
    uint32_t num_elements;
    uint32_t element_size;   // only meaningful when is_fixed == true
};

// Stamp the header into the first bytes of buf.
inline void WriteHeader(std::vector<uint8_t>& buf, const EncryptedValueHeader& header) {
    const size_t required = header.is_fixed ? kFixedHeaderLength : kVariableHeaderLength;
    if (buf.size() < required) {
        throw InvalidInputException("WriteHeader: buffer too small");
    }
    if (header.is_fixed) {
        buf[0] = kFixedSizeTag;
        write_u32_le_at(buf, kTagLength, header.num_elements);
        write_u32_le_at(buf, kTagLength + kSizeTLength, header.element_size);
    } else {
        buf[0] = kVariableSizeTag;
        write_u32_le_at(buf, kTagLength, header.num_elements);
    }
}

// Parse the wire-format header from the beginning of encrypted bytes.
inline EncryptedValueHeader ReadHeader(tcb::span<const uint8_t> bytes) {
    if (bytes.empty()) {
        throw InvalidInputException("ReadHeader: empty input");
    }

    EncryptedValueHeader header{};
    header.is_fixed = (bytes[0] == kFixedSizeTag);

    if (header.is_fixed) {
        if (bytes.size() < kFixedHeaderLength) {
            throw InvalidInputException("ReadHeader: truncated fixed-size header");
        }
        header.num_elements = read_u32_le(bytes, kTagLength);
        header.element_size = read_u32_le(bytes, kTagLength + kSizeTLength);
    } else {
        if (bytes.size() < kVariableHeaderLength) {
            throw InvalidInputException("ReadHeader: truncated variable-size header");
        }
        header.num_elements = read_u32_le(bytes, kTagLength);
        header.element_size = 0;
    }
    return header;
}

} // namespace dbps::processing
