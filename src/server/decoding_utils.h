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
#include <optional>
#include <map>
#include <variant>
#include <cstdint>
#include <array>
#include "enums.h"
#include "exceptions.h"
#include "enum_utils.h"

struct LevelAndValueBytes {
    std::vector<uint8_t> level_bytes;
    std::vector<uint8_t> value_bytes;
};

using TypedListValues = std::variant<
    std::vector<int32_t>,
    std::vector<int64_t>,
    std::vector<float>,
    std::vector<double>,
    std::vector<std::array<uint32_t, 3>>,     // For INT96
    std::vector<std::string>,                 // For BYTE_ARRAY and FIXED_LEN_BYTE_ARRAY
    std::vector<uint8_t>                      // For UNDEFINED, a plain untyped byte sequence.
>;

using namespace dbps::external;

/**
 * Calculates the total length of level bytes based on encoding attributes.
 * Assumes the input encoding attributes are already validated with the required keys and expected value types.
 * 
 * @param raw Raw binary data (currently unused but kept for future V1 implementation)
 * @param encoding_attribs Converted encoding attributes map
 * @return Total length of level bytes. Throws exceptions if calculation fails or page type is unsupported
 */
int CalculateLevelBytesLength(const std::vector<uint8_t>& raw,
    const std::map<std::string, std::variant<int32_t, bool, std::string>>& encoding_attribs);

/**
 * Split the input bytes in two parts, determined by the given index.
 * 
 * @param bytes The bytes to split
 * @param index The index at which to split (bytes before index go to level_bytes, bytes from index go to value_bytes)
 * @return LevelAndValueBytes structure with split bytes
 * @throws InvalidInputException if index is invalid
 */
LevelAndValueBytes Split(const std::vector<uint8_t>& bytes, int index);

/**
 * Parse the value bytes into a typed list based on the data type and format.
 * 
 * @param bytes The value bytes to parse
 * @param datatype The data type of the values
 * @param datatype_length Optional length for fixed-length types (required for FIXED_LEN_BYTE_ARRAY)
 * @param format The format of the data (currently only PLAIN is supported)
 * @return TypedListValues containing the parsed values
 * @throws DBPSUnsupportedException if format or datatype is unsupported
 * @throws InvalidInputException if the data is invalid or malformed
 */
TypedListValues ParseValueBytesIntoTypedList(
    const std::vector<uint8_t>& bytes,
    Type::type datatype,
    const std::optional<int>& datatype_length,
    Format::type format);

/**
 * Print a typed list in a human-readable format.
 * 
 * @param list The typed list to print
 * @return String representation of the typed list
 */
std::string PrintTypedList(const TypedListValues& list);
