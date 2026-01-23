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
#include "enums.h"
#include "../common/exceptions.h"
#include "enum_utils.h"
#include "../common/typed_list_values.h"
#include "../common/bytes_utils.h"

struct LevelAndValueBytes {
    std::vector<uint8_t> level_bytes;
    std::vector<uint8_t> value_bytes;
};

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
    const AttributesMap& encoding_attribs);

/**
 * Slice a flat byte buffer into RawValueBytes elements according to datatype/encoding.
 * This follows the Parquet specific encoding.
 */
std::vector<RawValueBytes> SliceValueBytesIntoRawBytes(
    const std::vector<uint8_t>& bytes,
    Type::type datatype,
    const std::optional<int>& datatype_length,
    Encoding::type encoding);

/**
 * Combine RawValueBytes elements back into a flat value-bytes buffer.
 */
std::vector<uint8_t> CombineRawBytesIntoValueBytes(
    const std::vector<RawValueBytes>& elements,
    Type::type datatype,
    const std::optional<int>& datatype_length,
    Encoding::type encoding);

/**
 * Decompresses and splits a Parquet page into level and value bytes.
 * Handles DATA_PAGE_V1, DATA_PAGE_V2 (including optional compression on value bytes),
 * and DICTIONARY_PAGE.
 */
LevelAndValueBytes DecompressAndSplit(
    const std::vector<uint8_t>& plaintext,
    CompressionCodec::type compression,
    const AttributesMap& encoding_attributes);

/**
 * Reverse of DecompressAndSplit: joins level/value bytes and applies compression
 * based on page type and encoding attributes.
 */
std::vector<uint8_t> CompressAndJoin(
    const std::vector<uint8_t>& level_bytes,
    const std::vector<uint8_t>& value_bytes,
    CompressionCodec::type compression,
    const AttributesMap& encoding_attributes);

/**
 * Parse the value bytes into a typed list based on the data type and encoding.
 * 
 * @param bytes The value bytes to parse
 * @param datatype The data type of the values
 * @param datatype_length Optional length for fixed-length types (required for FIXED_LEN_BYTE_ARRAY)
 * @param encoding The encoding of the data (currently only PLAIN is supported)
 * @return TypedListValues containing the parsed values
 * @throws DBPSUnsupportedException if encoding or datatype is unsupported
 * @throws InvalidInputException if the data is invalid or malformed
 */
TypedListValues ParseValueBytesIntoTypedList(
    const std::vector<uint8_t>& bytes,
    Type::type datatype,
    const std::optional<int>& datatype_length,
    Encoding::type encoding);

/**
 * Convert a typed list back into value bytes based on the data type and encoding.
 * This is the reverse operation of ParseValueBytesIntoTypedList.
 * 
 * @param list The typed list to convert
 * @param datatype The data type of the values
 * @param datatype_length Optional length for fixed-length types (required for FIXED_LEN_BYTE_ARRAY)
 * @param encoding The encoding of the data (currently only PLAIN is supported)
 * @return std::vector<uint8_t> containing the serialized value bytes
 * @throws DBPSUnsupportedException if encoding or datatype is unsupported
 * @throws InvalidInputException if the data is invalid or malformed
 */
std::vector<uint8_t> GetTypedListAsValueBytes(
    const TypedListValues& list,
    Type::type datatype,
    const std::optional<int>& datatype_length,
    Encoding::type encoding);
