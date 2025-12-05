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

#include <vector>
#include <cstdint>
#include <limits>
#include <cstring>
#include "exceptions.h"

// Little-endian helpers reused across modules
inline void append_u32_le(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

inline void append_i32_le(std::vector<uint8_t>& out, int32_t v) {
    append_u32_le(out, static_cast<uint32_t>(v));
}

inline void append_u64_le(std::vector<uint8_t>& out, uint64_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 32) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 40) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 48) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 56) & 0xFF));
}

inline void append_i64_le(std::vector<uint8_t>& out, int64_t v) {
    append_u64_le(out, static_cast<uint64_t>(v));
}

inline void append_f32_le(std::vector<uint8_t>& out, float v) {
    uint32_t bits = 0;
    std::memcpy(&bits, &v, sizeof(bits));
    append_u32_le(out, bits);
}

inline void append_f64_le(std::vector<uint8_t>& out, double v) {
    uint64_t bits = 0;
    std::memcpy(&bits, &v, sizeof(bits));
    append_u64_le(out, bits);
}

inline uint32_t read_u32_le(const std::vector<uint8_t>& in, size_t offset) {
    return static_cast<uint32_t>(in[offset]) |
        (static_cast<uint32_t>(in[offset + 1]) << 8) |
        (static_cast<uint32_t>(in[offset + 2]) << 16) |
        (static_cast<uint32_t>(in[offset + 3]) << 24);
}

struct SplitBytesPair {
    std::vector<uint8_t> leading;
    std::vector<uint8_t> trailing;
};

inline std::vector<uint8_t> Join(const std::vector<uint8_t>& leading, const std::vector<uint8_t>& trailing) {
    std::vector<uint8_t> result;
    result.reserve(leading.size() + trailing.size());
    result.insert(result.end(), leading.begin(), leading.end());
    result.insert(result.end(), trailing.begin(), trailing.end());
    return result;
}

inline SplitBytesPair Split(const std::vector<uint8_t>& bytes, int index) {
    SplitBytesPair result;

    if (index < 0 || index > static_cast<int>(bytes.size())) {
        throw InvalidInputException("Invalid index for splitting bytes: " + std::to_string(index));
    }
    result.leading = std::vector<uint8_t>(bytes.begin(), bytes.begin() + index);
    result.trailing = std::vector<uint8_t>(bytes.begin() + index, bytes.end());

    return result;
}

inline std::vector<uint8_t> JoinWithLengthPrefix(const std::vector<uint8_t>& leading, const std::vector<uint8_t>& trailing) {
    if (leading.size() > std::numeric_limits<uint32_t>::max()) {
        throw InvalidInputException("Leading bytes size exceeds maximum representable value");
    }
    
    uint32_t leading_length = static_cast<uint32_t>(leading.size());
    std::vector<uint8_t> result;
    result.reserve(4 + leading.size() + trailing.size());
    
    result.push_back(leading_length & 0xFF);
    result.push_back((leading_length >> 8) & 0xFF);
    result.push_back((leading_length >> 16) & 0xFF);
    result.push_back((leading_length >> 24) & 0xFF);
    
    result.insert(result.end(), leading.begin(), leading.end());
    result.insert(result.end(), trailing.begin(), trailing.end());
    
    return result;
}

inline SplitBytesPair SplitWithLengthPrefix(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 4) {
        throw InvalidInputException("Invalid length-prefixed data: insufficient bytes for length prefix");
    }
    
    uint32_t leading_length = static_cast<uint32_t>(bytes[0]) |
                              (static_cast<uint32_t>(bytes[1]) << 8) |
                              (static_cast<uint32_t>(bytes[2]) << 16) |
                              (static_cast<uint32_t>(bytes[3]) << 24);
    
    if (bytes.size() < 4 + leading_length) {
        throw InvalidInputException("Invalid length-prefixed data: insufficient bytes for leading data (expected " +
                                   std::to_string(4 + leading_length) + ", got " + std::to_string(bytes.size()) + ")");
    }
    
    SplitBytesPair result;
    
    result.leading = std::vector<uint8_t>(bytes.begin() + 4, bytes.begin() + 4 + leading_length);
    result.trailing = std::vector<uint8_t>(bytes.begin() + 4 + leading_length, bytes.end());
    
    return result;
}

