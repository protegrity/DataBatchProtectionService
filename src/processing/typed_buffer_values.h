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

#include <sstream>
#include <string>
#include <variant>
#include "typed_buffer_codecs.h"
#include "typed_buffer.h"

namespace dbps::processing {

struct Int96 {
    int32_t lo;
    int32_t mid;
    int32_t hi;
};

inline constexpr char kI32TypeName[] = "INT32";
inline constexpr char kI64TypeName[] = "INT64";
inline constexpr char kF32TypeName[] = "FLOAT";
inline constexpr char kF64TypeName[] = "DOUBLE";
inline constexpr char kInt96TypeName[] = "INT96";

using TypedBufferI32 = ByteBuffer<PlainValueCodec<int32_t, kI32TypeName>>;
using TypedBufferI64 = ByteBuffer<PlainValueCodec<int64_t, kI64TypeName>>;
using TypedBufferFloat = ByteBuffer<PlainValueCodec<float, kF32TypeName>>;
using TypedBufferDouble = ByteBuffer<PlainValueCodec<double, kF64TypeName>>;
using TypedBufferInt96 = ByteBuffer<PlainValueCodec<Int96, kInt96TypeName>>;
using TypedBufferRawBytesFixedSized = ByteBuffer<RawBytesFixedSizedCodec>;
using TypedBufferRawBytesVariableSized = ByteBuffer<RawBytesVariableSizedCodec>;

using TypedValuesBuffer = std::variant<
    TypedBufferI32,
    TypedBufferI64,
    TypedBufferFloat,
    TypedBufferDouble,
    TypedBufferInt96,
    TypedBufferRawBytesFixedSized,
    TypedBufferRawBytesVariableSized
>;

// Printable string representation of the typed buffer
inline std::string PrintableTypedValuesBuffer(const TypedValuesBuffer& buffer) {
    return std::visit([](const auto& typed_buffer) -> std::string {
        using BufferType = std::decay_t<decltype(typed_buffer)>;
        using ValueType = typename BufferType::value_type;

        std::ostringstream out;
        const size_t num_elements = typed_buffer.GetNumElements();

        out << BufferType::type_name() << " (" << num_elements << " elements):\n";

        for (size_t i = 0; i < num_elements; ++i) {
            const auto element = typed_buffer.GetElement(i);
            if constexpr (std::is_same_v<ValueType, Int96>) {
                out << "  [" << i << "] [" << element.lo << ", "
                    << element.mid << ", " << element.hi << "]\n";
            } else if constexpr (std::is_same_v<ValueType, std::string_view>) {
                out << "  [" << i << "] \"" << element
                    << "\" (length: " << element.size() << ")\n";
            } else if constexpr (std::is_same_v<ValueType, tcb::span<const uint8_t>>) {
                out << "  [" << i << "] <" << element.size() << " bytes>\n";
            } else {
                out << "  [" << i << "] " << element << "\n";
            }
        }

        return out.str();
    }, buffer);
}

} // namespace dbps::processing
