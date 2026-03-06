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
using TypedBufferStringFixedSized = ByteBuffer<StringFixedSizedCodec>;
using TypedBufferStringVariableSized = ByteBuffer<StringVariableSizedCodec>;

using TypedValuesBuffer = std::variant<
    TypedBufferI32,
    TypedBufferI64,
    TypedBufferFloat,
    TypedBufferDouble,
    TypedBufferInt96,
    TypedBufferStringFixedSized,
    TypedBufferStringVariableSized
>;
} // namespace dbps::processing
