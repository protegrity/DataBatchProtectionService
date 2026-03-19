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
#include <tcb/span.hpp>
#include "exceptions.h"

inline constexpr size_t kSizePrefixBytes = sizeof(uint32_t);

// Utility functions for little-endian number reading and writing (vectors and spans)

inline void append_u32_le(std::vector<uint8_t>& out, uint32_t v) {
    const size_t offset = out.size();
    out.resize(offset + 4);
    out[offset + 0] = static_cast<uint8_t>(v & 0xFF);
    out[offset + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    out[offset + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    out[offset + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

inline void append_i32_le(std::vector<uint8_t>& out, int32_t v) {
    append_u32_le(out, static_cast<uint32_t>(v));
}

inline void append_u64_le(std::vector<uint8_t>& out, uint64_t v) {
    const size_t offset = out.size();
    out.resize(offset + 8);
    out[offset + 0] = static_cast<uint8_t>(v & 0xFF);
    out[offset + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    out[offset + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    out[offset + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    out[offset + 4] = static_cast<uint8_t>((v >> 32) & 0xFF);
    out[offset + 5] = static_cast<uint8_t>((v >> 40) & 0xFF);
    out[offset + 6] = static_cast<uint8_t>((v >> 48) & 0xFF);
    out[offset + 7] = static_cast<uint8_t>((v >> 56) & 0xFF);
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

inline void write_u32_le_at(std::vector<uint8_t>& buf, size_t offset, uint32_t v) {
    buf[offset + 0] = static_cast<uint8_t>(v & 0xFF);
    buf[offset + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    buf[offset + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    buf[offset + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

inline uint32_t read_u32_le(const std::vector<uint8_t>& in, size_t offset) {
    return static_cast<uint32_t>(in[offset]) |
        (static_cast<uint32_t>(in[offset + 1]) << 8) |
        (static_cast<uint32_t>(in[offset + 2]) << 16) |
        (static_cast<uint32_t>(in[offset + 3]) << 24);
}

inline uint32_t read_u32_le(tcb::span<const uint8_t> in, size_t offset) {
    return static_cast<uint32_t>(in[offset]) |
        (static_cast<uint32_t>(in[offset + 1]) << 8) |
        (static_cast<uint32_t>(in[offset + 2]) << 16) |
        (static_cast<uint32_t>(in[offset + 3]) << 24);
}

// Utility functions for reading and writing with templated types.

template <class T>
inline T read_le(const uint8_t* p) {
    if constexpr (std::is_same_v<T, int32_t>) {
        const uint32_t v =
            (static_cast<uint32_t>(p[0])      ) |
            (static_cast<uint32_t>(p[1]) <<  8) |
            (static_cast<uint32_t>(p[2]) << 16) |
            (static_cast<uint32_t>(p[3]) << 24);
        return static_cast<int32_t>(v);
    } else if constexpr (std::is_same_v<T, int64_t>) {
        const uint64_t v =
            (static_cast<uint64_t>(p[0])      ) |
            (static_cast<uint64_t>(p[1]) <<  8) |
            (static_cast<uint64_t>(p[2]) << 16) |
            (static_cast<uint64_t>(p[3]) << 24) |
            (static_cast<uint64_t>(p[4]) << 32) |
            (static_cast<uint64_t>(p[5]) << 40) |
            (static_cast<uint64_t>(p[6]) << 48) |
            (static_cast<uint64_t>(p[7]) << 56);
        return static_cast<int64_t>(v);
    } else if constexpr (std::is_same_v<T, float>) {
        const uint32_t bits =
            (static_cast<uint32_t>(p[0])      ) |
            (static_cast<uint32_t>(p[1]) <<  8) |
            (static_cast<uint32_t>(p[2]) << 16) |
            (static_cast<uint32_t>(p[3]) << 24);
        float value;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    } else if constexpr (std::is_same_v<T, double>) {
        const uint64_t bits =
            (static_cast<uint64_t>(p[0])      ) |
            (static_cast<uint64_t>(p[1]) <<  8) |
            (static_cast<uint64_t>(p[2]) << 16) |
            (static_cast<uint64_t>(p[3]) << 24) |
            (static_cast<uint64_t>(p[4]) << 32) |
            (static_cast<uint64_t>(p[5]) << 40) |
            (static_cast<uint64_t>(p[6]) << 48) |
            (static_cast<uint64_t>(p[7]) << 56);
        double value;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    } else {
        throw InvalidInputException("read_le<T>: unsupported type");
    }
}

template <class T>
inline void write_le(const T& value, uint8_t* p) {
    if constexpr (std::is_same_v<T, int32_t>) {
        const uint32_t v = static_cast<uint32_t>(value);
        p[0] = static_cast<uint8_t>( v        & 0xFF);
        p[1] = static_cast<uint8_t>((v >>  8) & 0xFF);
        p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    } else if constexpr (std::is_same_v<T, int64_t>) {
        const uint64_t v = static_cast<uint64_t>(value);
        p[0] = static_cast<uint8_t>( v        & 0xFF);
        p[1] = static_cast<uint8_t>((v >>  8) & 0xFF);
        p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
        p[4] = static_cast<uint8_t>((v >> 32) & 0xFF);
        p[5] = static_cast<uint8_t>((v >> 40) & 0xFF);
        p[6] = static_cast<uint8_t>((v >> 48) & 0xFF);
        p[7] = static_cast<uint8_t>((v >> 56) & 0xFF);
    } else if constexpr (std::is_same_v<T, float>) {
        uint32_t bits;
        std::memcpy(&bits, &value, sizeof(bits));
        p[0] = static_cast<uint8_t>( bits        & 0xFF);
        p[1] = static_cast<uint8_t>((bits >>  8) & 0xFF);
        p[2] = static_cast<uint8_t>((bits >> 16) & 0xFF);
        p[3] = static_cast<uint8_t>((bits >> 24) & 0xFF);
    } else if constexpr (std::is_same_v<T, double>) {
        uint64_t bits;
        std::memcpy(&bits, &value, sizeof(bits));
        p[0] = static_cast<uint8_t>( bits        & 0xFF);
        p[1] = static_cast<uint8_t>((bits >>  8) & 0xFF);
        p[2] = static_cast<uint8_t>((bits >> 16) & 0xFF);
        p[3] = static_cast<uint8_t>((bits >> 24) & 0xFF);
        p[4] = static_cast<uint8_t>((bits >> 32) & 0xFF);
        p[5] = static_cast<uint8_t>((bits >> 40) & 0xFF);
        p[6] = static_cast<uint8_t>((bits >> 48) & 0xFF);
        p[7] = static_cast<uint8_t>((bits >> 56) & 0xFF);
    } else {
        throw InvalidInputException("write_le<T>: unsupported type");
    }
}

// Utility functions for little-endian number reading and writing (pointers)

inline void write_u32_le(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

inline uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
        (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) |
        (static_cast<uint32_t>(p[3]) << 24);
}

// Utility functions for splitting and joining byte vectors.

struct BytesPair {
    std::vector<uint8_t> leading;
    std::vector<uint8_t> trailing;
};

struct SpansPair {
    tcb::span<const uint8_t> leading;
    tcb::span<const uint8_t> trailing;
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
 * @return BytesPair structure with split bytes
 * @throws InvalidInputException if index is invalid
 */
inline BytesPair Split(const std::vector<uint8_t>& bytes, int index) {
    BytesPair result;

    if (index < 0 || index > static_cast<int>(bytes.size())) {
        throw InvalidInputException("Invalid index for splitting bytes: " + std::to_string(index));
    }
    result.leading = std::vector<uint8_t>(bytes.begin(), bytes.begin() + index);
    result.trailing = std::vector<uint8_t>(bytes.begin() + index, bytes.end());

    return result;
}

/**
 * Split a span into two non-owning spans at index.
 *
 * @param bytes The span to split
 * @param index The index at which to split (bytes before index go to leading, bytes from index go to trailing)
 * @return SpansPair structure with split spans
 * @throws InvalidInputException if index is invalid
 */
inline SpansPair Split(tcb::span<const uint8_t> bytes, int index) {
    if (index < 0 || index > static_cast<int>(bytes.size())) {
        throw InvalidInputException("Invalid index for splitting bytes: " + std::to_string(index));
    }
    const size_t split_index = static_cast<size_t>(index);
    return SpansPair{
        tcb::span<const uint8_t>(bytes.data(), split_index),
        tcb::span<const uint8_t>(bytes.data() + split_index, bytes.size() - split_index)};
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
    result.reserve(kSizePrefixBytes + leading.size() + trailing.size());
    
    // Prepend 4-byte length
    append_u32_le(result, leading_length);
    
    // Append leading and trailing bytes
    result.insert(result.end(), leading.begin(), leading.end());
    result.insert(result.end(), trailing.begin(), trailing.end());
    
    return result;
}

/**
 * Parse a self-contained byte span that was created with JoinWithLengthPrefix.
 * Extracts leading and trailing span views based on the embedded length prefix.
 *
 * @param bytes The combined bytes with length prefix
 * @return SpansPair structure with leading and trailing span views
 * @throws InvalidInputException if the data is invalid or malformed
 */
inline SpansPair SplitWithLengthPrefix(tcb::span<const uint8_t> bytes) {
    if (bytes.size() < kSizePrefixBytes) {
        throw InvalidInputException("Invalid length-prefixed data: insufficient bytes for length prefix");
    }

    uint32_t leading_length = read_u32_le(bytes, 0);

    if (bytes.size() < kSizePrefixBytes + leading_length) {
        throw InvalidInputException("Invalid length-prefixed data: insufficient bytes for leading data (expected " +
                                   std::to_string(kSizePrefixBytes + leading_length) + ", got " + std::to_string(bytes.size()) + ")");
    }

    auto payload = tcb::span<const uint8_t>(
        bytes.data() + kSizePrefixBytes,
        bytes.size() - kSizePrefixBytes);
    return Split(payload, static_cast<int>(leading_length));
}

/**
 * Parse a self-contained byte vector that was created with JoinWithLengthPrefix.
 * Extracts the leading and trailing parts based on the embedded length prefix.
 * 
 * @param bytes The combined bytes with length prefix
 * @return BytesPair structure with leading and trailing bytes
 * @throws InvalidInputException if the data is invalid or malformed
 */
 inline BytesPair SplitWithLengthPrefix(const std::vector<uint8_t>& bytes) {
    const auto spans = SplitWithLengthPrefix(tcb::span<const uint8_t>(bytes));
    return BytesPair{
        std::vector<uint8_t>(spans.leading.begin(), spans.leading.end()),
        std::vector<uint8_t>(spans.trailing.begin(), spans.trailing.end())};
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

// Helper function to convert string to binary data and vice versa

inline std::vector<uint8_t> StringToBytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

inline std::string BytesToString(tcb::span<const uint8_t> span) {
    std::string result;
    result.reserve(span.size());
    for (const uint8_t byte : span) {
        result += static_cast<char>(byte);
    }
    return result;
}
