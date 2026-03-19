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
#include <cstring>
#include <string_view>
#include <tcb/span.hpp>
#include "bytes_utils.h"
#include "exceptions.h"

namespace dbps::processing {

// The values in Int96 of low/mid/hi are stored in little endian order.
// The order of low/mid/hi in the C++ struct should be kept, otherwise the codec will yield incorrect values.
struct Int96 {
    int32_t lo;
    int32_t mid;
    int32_t hi;
};

template <class T, const char* TypeName>
struct PlainValueCodec {
    using value_type = T;
    static constexpr bool is_fixed_sized = true;

    // Compile-time check that the type is trivially copyable (can be copied simply by memcpy)
    static_assert(std::is_trivially_copyable_v<T>,
                  "PlainValueCodec requires trivially copyable T");

    static constexpr std::string_view type_name() noexcept {
        return std::string_view(TypeName);
    }

    constexpr size_t element_size() const noexcept {
        return sizeof(T);
    }

    inline value_type Decode(tcb::span<const uint8_t> read_span) const {
        if (read_span.size() != sizeof(T)) {
            throw InvalidInputException("Decode: read_span size does not match sizeof(T)");
        }
        return read_le<T>(read_span.data());
    }

    inline void Encode(const value_type& value, tcb::span<uint8_t> write_span) const {
        if (write_span.size() != sizeof(T)) {
            throw InvalidInputException("Encode: write_span size does not match sizeof(T)");
        }
        write_le<T>(value, write_span.data());
    }
};

struct Int96Codec {
    using value_type = Int96;
    static constexpr bool is_fixed_sized = true;
    static constexpr size_t kI32Size = sizeof(int32_t);

    static constexpr std::string_view type_name() noexcept {
        return "INT96";
    }

    static constexpr size_t element_size() noexcept {
        return sizeof(Int96);
    }

    inline value_type Decode(tcb::span<const uint8_t> read_span) const {
        if (read_span.size() != sizeof(Int96)) {
            throw InvalidInputException("Decode: read_span size does not match Int96 element size");
        }
        const uint8_t* p = read_span.data();
        return Int96{
            read_le<int32_t>(p + 0 * kI32Size),
            read_le<int32_t>(p + 1 * kI32Size),
            read_le<int32_t>(p + 2 * kI32Size)};
    }

    inline void Encode(const value_type& value, tcb::span<uint8_t> write_span) const {
        if (write_span.size() != sizeof(Int96)) {
            throw InvalidInputException("Encode: write_span size does not match Int96 element size");
        }
        uint8_t* p = write_span.data();
        write_le<int32_t>(value.lo, p + 0 * kI32Size);
        write_le<int32_t>(value.mid, p + 1 * kI32Size);
        write_le<int32_t>(value.hi, p + 2 * kI32Size);
    }
};

struct RawBytesFixedSizedCodec {
    using value_type = tcb::span<const uint8_t>;
    static constexpr bool is_fixed_sized = true;

    explicit RawBytesFixedSizedCodec(size_t element_size_bytes) : element_size_bytes_(element_size_bytes) {
        if (element_size_bytes_ == 0) {
            throw InvalidInputException("RawBytesFixedSizedCodec requires element_size_bytes > 0");
        }
    }

    static constexpr std::string_view type_name() noexcept {
        return "raw bytes (fixed-length)";
    }

    size_t element_size() const noexcept {
        return element_size_bytes_;
    }

    inline value_type Decode(tcb::span<const uint8_t> read_span) const noexcept {
        return read_span;
    }

    inline void Encode(const value_type& value, tcb::span<uint8_t> write_span) const {
        if (value.size() != write_span.size()) {
            throw InvalidInputException("Encode: value size does not match write_span size");
        }
        std::memcpy(write_span.data(), value.data(), write_span.size());
    }

    private:
        size_t element_size_bytes_;
};

struct RawBytesVariableSizedCodec {
    using value_type = tcb::span<const uint8_t>;
    static constexpr bool is_fixed_sized = false;

    static constexpr std::string_view type_name() noexcept {
        return "raw bytes (variable-length)";
    }

    size_t element_size() const {
        throw InvalidInputException("RawBytesVariableSizedCodec does not have a fixed element size");
    }

    inline value_type Decode(tcb::span<const uint8_t> read_span) const noexcept {
        return read_span;
    }

    inline void Encode(const value_type& value, tcb::span<uint8_t> write_span) const {
        if (value.size() != write_span.size()) {
            throw InvalidInputException("Encode: value size does not match write_span size");
        }
        std::memcpy(write_span.data(), value.data(), write_span.size());
    }
};

} // namespace dbps::processing
