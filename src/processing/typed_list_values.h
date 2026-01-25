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
#include <string>
#include <variant>
#include <cstdint>
#include <array>
#include "enums.h"

using namespace dbps::external;

using TypedListValues = std::variant<
    std::vector<int32_t>,
    std::vector<int64_t>,
    std::vector<float>,
    std::vector<double>,
    std::vector<std::array<uint32_t, 3>>,     // For INT96
    std::vector<std::string>                  // For BYTE_ARRAY and FIXED_LEN_BYTE_ARRAY
>;

/**
 * Type alias for raw value bytes.
 */
using RawValueBytes = std::vector<uint8_t>;

/**
 * Convert a vector of raw value bytes into a typed list based on the provided datatype.
 * The numeric representations are expected to be little-endian.
 *
 * @throws std::runtime_error if element sizes are inconsistent with the datatype
 *         or if the datatype is unsupported.
 */
TypedListValues BuildTypedListFromRawBytes(
    Type::type datatype,
    const std::vector<RawValueBytes>& elements_bytes);

/**
 * Convert a typed list of values into their raw little-endian byte representation.
 * Produces one RawValueBytes per input element.
 *
 * @throws at compile-time if an unsupported variant alternative is provided
 *         (static_assert in implementation).
 */
std::vector<RawValueBytes> BuildRawBytesFromTypedListValues(
    const TypedListValues& elements);

/**
 * Print a typed list in a human-readable format.
 * 
 * @param list The typed list to print
 * @return String representation of the typed list
 */
std::string TypedListToString(const TypedListValues& list);

