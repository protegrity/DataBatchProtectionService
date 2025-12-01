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
#include "enums.h"
#include "enum_utils.h"
#include "exceptions.h"

using namespace dbps::external;
using namespace dbps::enum_utils;

namespace dbps::compression {

/**
 * Compress bytes using the compression codec.
 * 
 * @param bytes The bytes to compress
 * @param compression The compression codec to use
 * @return Compressed bytes, or original bytes if UNCOMPRESSED
 * @throws DBPSUnsupportedException if the compression codec is not supported
 */
std::vector<uint8_t> Compress(const std::vector<uint8_t>& bytes, CompressionCodec::type compression);

/**
 * Decompress bytes using the compression codec.
 * 
 * @param bytes The bytes to decompress
 * @param compression The compression codec that was used to compress the bytes
 * @return Decompressed bytes, or original bytes if UNCOMPRESSED
 * @throws DBPSUnsupportedException if the compression codec is not supported
 */
std::vector<uint8_t> Decompress(const std::vector<uint8_t>& bytes, CompressionCodec::type compression);

} // namespace dbps::compression
