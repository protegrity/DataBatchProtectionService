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
#include <string_view>
#include <tcb/span.hpp>
#include "exceptions.h"

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

    value_type Decode(tcb::span<const uint8_t> read_span) const {
        if (read_span.size() != sizeof(T)) {
            throw InvalidInputException("Decode: read_span size does not match sizeof(T)");
        }
        T value;
        std::memcpy(&value, read_span.data(), sizeof(T));
        return value;
    }

    void Encode(const value_type& value, tcb::span<uint8_t> write_span) const {
        if (write_span.size() != sizeof(T)) {
            throw InvalidInputException("Encode: write_span size does not match sizeof(T)");
        }
        std::memcpy(write_span.data(), &value, sizeof(T));
    }
};

struct StringFixedSizedCodec {
    using value_type = std::string_view;
    static constexpr bool is_fixed_sized = true;

    explicit StringFixedSizedCodec(size_t element_size_bytes = 0) : element_size_bytes_(element_size_bytes) {
        if (element_size_bytes_ <= 0) {
            throw InvalidInputException("StringFixedSizedCodec requires element_size_bytes > 0");
        }            
    }

    static constexpr std::string_view type_name() noexcept {
        return "string (fixed-length)";
    }

    constexpr size_t element_size() const noexcept {
        return element_size_bytes_;
    }

    value_type Decode(tcb::span<const uint8_t> read_span) const {
        if (read_span.size() != element_size_bytes_) {
            throw InvalidInputException("Decode: read_span size does not match element_size_bytes");
        }
        return std::string_view(
            reinterpret_cast<const char*>(read_span.data()),
            read_span.size());
    }

    void Encode(const value_type& value, tcb::span<uint8_t> write_span) const {
        if (write_span.size() != element_size_bytes_) {
            throw InvalidInputException("Encode: write_span size does not match element_size_bytes");
        }
        if (value.size() != write_span.size()) {
            throw InvalidInputException("Encode: value size does not match write_span size");
        }
        std::memcpy(write_span.data(), value.data(), write_span.size());
    }

    private:
        size_t element_size_bytes_;
};

struct StringVariableSizedCodec {
    using value_type = std::string_view;
    static constexpr bool is_fixed_sized = false;

    static constexpr std::string_view type_name() noexcept {
        return "string (variable-length)";
    }

    size_t element_size() const {
        throw InvalidInputException("StringVariableSizedCodec does not have a fixed element size");
    }

    value_type Decode(tcb::span<const uint8_t> read_span) const noexcept {
        return std::string_view(
            reinterpret_cast<const char*>(read_span.data()),
            read_span.size());
    }

    void Encode(const value_type& value, tcb::span<uint8_t> write_span) const {
        if (value.size() != write_span.size()) {
            throw InvalidInputException("Encode: value size does not match write_span size");
        }
        std::memcpy(write_span.data(), value.data(), write_span.size());
    }
};
