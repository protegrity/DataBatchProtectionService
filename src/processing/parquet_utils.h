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
#include <tcb/span.hpp>
#include "enums.h"
#include "../common/exceptions.h"
#include "enum_utils.h"
#include "typed_buffer_values.h"
#include "../common/bytes_utils.h"

struct LevelAndValueBytes {
    std::vector<uint8_t> level_bytes;
    std::vector<uint8_t> value_bytes;
    size_t num_elements;
};

using namespace dbps::external;

// -----------------------------------------------------------------------------
// Helper functions for lower-level Parquet metadata and level bytes parsing.
// -----------------------------------------------------------------------------

/**
 * Calculates the total length of level bytes based on encoding attributes.
 * Assumes the input encoding attributes are already validated with the required keys and expected value types.
 * 
 * @param raw Raw binary data (currently unused but kept for future V1 implementation)
 * @param encoding_attribs Converted encoding attributes map
 * @return Total length of level bytes. Throws exceptions if calculation fails or page type is unsupported
 */
int CalculateLevelBytesLength(tcb::span<const uint8_t> raw,
    const AttributesMap& encoding_attribs);

/**
 * Decode DATA_PAGE_V1 definition-level payload bytes (hybrid RLE/bit-packed)
 * and return the number of present (non-null) values.
 *
 * @param def_payload Definition-level payload bytes only (without [u32 length] prefix)
 * @param num_values Total logical values in page (includes nulls)
 * @param max_def_level Maximum definition level for the column
 * @return Count of decoded definition levels equal to max_def_level
 */
size_t CountPresentFromDefinitionLevelsV1(
    tcb::span<const uint8_t> def_payload,
    int32_t num_values,
    int32_t max_def_level);

// -----------------------------------------------------------------------------
// Functions to decompress and split a Parquet page into level and value bytes.
// -----------------------------------------------------------------------------

/**
 * Decompresses and splits a Parquet page into level and value bytes.
 * Handles DATA_PAGE_V1, DATA_PAGE_V2 (including optional compression on value bytes),
 * and DICTIONARY_PAGE.
 */
 LevelAndValueBytes DecompressAndSplit(
    tcb::span<const uint8_t> plaintext,
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


// -----------------------------------------------------------------------------
// Functions for zero-copy reinterpretation of raw value bytes into a typed buffer.
// -----------------------------------------------------------------------------

/**
 * Zero-copy reinterpretation of raw value bytes into a typed buffer.
 * Returns a TypedValuesBuffer variant holding the appropriate ByteBuffer<Codec>
 * for the given Parquet datatype.
 *
 * The returned buffer holds a non-owning view into value_bytes.
 * The caller must keep the backing data alive for as long as the buffer is used.
 *
 * @param value_bytes Raw value bytes (span must outlive the returned buffer)
 * @param datatype Parquet physical type
 * @param datatype_length Required for FIXED_LEN_BYTE_ARRAY (must be > 0)
 * @param encoding Only PLAIN is currently supported
 * @throws DBPSUnsupportedException for RLE_DICTIONARY, BOOLEAN, or non-PLAIN encodings
 * @throws InvalidInputException for invalid datatype_length on FIXED_LEN_BYTE_ARRAY
 */
dbps::processing::TypedValuesBuffer ReinterpretValueBytesAsTypedValuesBuffer(
    tcb::span<const uint8_t> value_bytes,
    size_t num_elements,
    Type::type datatype,
    const std::optional<int>& datatype_length,
    Encoding::type encoding);

/**
 * Finalize a typed buffer and return the raw value bytes.
 * Consumes the buffer via rvalue-reference; caller must pass std::move(buffer).
 * Example:
 *   std::vector<uint8_t> value_bytes = GetTypedValuesBufferAsValueBytes(std::move(buf));
 */
std::vector<uint8_t> GetTypedValuesBufferAsValueBytes(
    dbps::processing::TypedValuesBuffer&& buffer);

// -----------------------------------------------------------------------------
