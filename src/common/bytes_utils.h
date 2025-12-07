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
#include <map>
#include <string>
#include <variant>
#include <cassert>
#include "exceptions.h"

// Utility functions for little-endian number reading and writing.

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

// Utility functions for splitting and joining byte vectors.

struct SplitBytesPair {
    std::vector<uint8_t> leading;
    std::vector<uint8_t> trailing;
};

/**
 * Join two byte vectors into a single vector.
 * This is the converse operation of Split - concatenates leading and trailing bytes.
 * 
 * @param leading The first part of the bytes
 * @param trailing The second part of the bytes
 * @return Combined bytes vector with leading followed by trailing
 */
inline std::vector<uint8_t> Join(const std::vector<uint8_t>& leading, const std::vector<uint8_t>& trailing) {
    std::vector<uint8_t> result;
    result.reserve(leading.size() + trailing.size());
    result.insert(result.end(), leading.begin(), leading.end());
    result.insert(result.end(), trailing.begin(), trailing.end());
    return result;
}

/**
 * Split the input bytes in two parts, determined by the given index.
 * 
 * @param bytes The bytes to split
 * @param index The index at which to split (bytes before index go to leading, bytes from index go to trailing)
 * @return SplitBytesPair structure with split bytes
 * @throws InvalidInputException if index is invalid
 */
inline SplitBytesPair Split(const std::vector<uint8_t>& bytes, int index) {
    SplitBytesPair result;

    if (index < 0 || index > static_cast<int>(bytes.size())) {
        throw InvalidInputException("Invalid index for splitting bytes: " + std::to_string(index));
    }
    result.leading = std::vector<uint8_t>(bytes.begin(), bytes.begin() + index);
    result.trailing = std::vector<uint8_t>(bytes.begin() + index, bytes.end());

    return result;
}

/**
 * Join two byte vectors with length prefix, making it self-contained and parseable.
 * The output format is: [4-byte length of leading][leading bytes][trailing bytes]
 * This allows the split point to be recovered when parsing later.
 * 
 * @param leading The first part of the bytes
 * @param trailing The second part of the bytes
 * @return Combined bytes vector with length prefix, leading, then trailing
 * @throws InvalidInputException if leading size exceeds maximum representable value (2^32 - 1)
 */
inline std::vector<uint8_t> JoinWithLengthPrefix(const std::vector<uint8_t>& leading, const std::vector<uint8_t>& trailing) {
    if (leading.size() > std::numeric_limits<uint32_t>::max()) {
        throw InvalidInputException("Leading bytes size exceeds maximum representable value");
    }
    
    // Calculate the length of the leading bytes
    uint32_t leading_length = static_cast<uint32_t>(leading.size());
    std::vector<uint8_t> result;
    result.reserve(4 + leading.size() + trailing.size());
    
    // Prepend 4-byte length
    append_u32_le(result, leading_length);
    
    // Append leading and trailing bytes
    result.insert(result.end(), leading.begin(), leading.end());
    result.insert(result.end(), trailing.begin(), trailing.end());
    
    return result;
}

/**
 * Parse a self-contained byte vector that was created with JoinWithLengthPrefix.
 * Extracts the leading and trailing parts based on the embedded length prefix.
 * 
 * @param bytes The combined bytes with length prefix
 * @return SplitBytesPair structure with leading and trailing bytes
 * @throws InvalidInputException if the data is invalid or malformed
 */
inline SplitBytesPair SplitWithLengthPrefix(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 4) {
        throw InvalidInputException("Invalid length-prefixed data: insufficient bytes for length prefix");
    }
    
    // Read 4-byte length
    uint32_t leading_length = read_u32_le(bytes, 0);
    
    if (bytes.size() < 4 + leading_length) {
        throw InvalidInputException("Invalid length-prefixed data: insufficient bytes for leading data (expected " +
                                   std::to_string(4 + leading_length) + ", got " + std::to_string(bytes.size()) + ")");
    }
    
    SplitBytesPair result;
    
    // Extract leading bytes (skip the 4-byte length prefix)
    result.leading = std::vector<uint8_t>(bytes.begin() + 4, bytes.begin() + 4 + leading_length);

    // Extract trailing bytes (everything after leading)
    result.trailing = std::vector<uint8_t>(bytes.begin() + 4 + leading_length, bytes.end());
    
    return result;
}

// Utility functions for creating an AttributesMap

// Common alias for converted encoding attributes used across modules.
// Numeric values are captured as int32_t.
using AttributesMap = std::map<std::string, std::variant<int32_t, bool, std::string>>;

inline const std::string& GetRequiredAttribute(
    const std::map<std::string, std::string>& attributes,
    const std::string& key) {
    auto it = attributes.find(key);
    if (it == attributes.end()) {
        throw InvalidInputException("Required encoding attribute [" + key + "] is missing");
    }
    return it->second;
}

inline int32_t AddIntAttribute(
    AttributesMap& out,
    const std::map<std::string, std::string>& attributes,
    const std::string& key) {
    const std::string& value = GetRequiredAttribute(attributes, key);
    try {
        int32_t value_int = static_cast<int32_t>(std::stol(value));
        assert(value_int >= 0);
        out[key] = value_int;
        return value_int;
    } catch (const std::exception& e) {
        throw InvalidInputException(
            "Failed to convert [" + key + "] with value [" + value + "] to int: " + e.what());
    }
}

inline bool AddBoolAttribute(
    AttributesMap& out,
    const std::map<std::string, std::string>& attributes,
    const std::string& key) {
    const std::string& value = GetRequiredAttribute(attributes, key);
    if (value == "true") {
        out[key] = true;
        return true;
    } else if (value == "false") {
        out[key] = false;
        return false;
    } else {
        throw InvalidInputException(
            "Failed to convert [" + key + "] with value [" + value + "] to bool");
    }
}

inline std::string AddStringAttribute(
    AttributesMap& out,
    const std::map<std::string, std::string>& attributes,
    const std::string& key) {
    const std::string& value = GetRequiredAttribute(attributes, key);
    out[key] = value;
    return value;
}
