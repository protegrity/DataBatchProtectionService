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

#include "compression_utils.h"
#include <snappy.h>

using namespace dbps::external;
using namespace dbps::enum_utils;

std::vector<uint8_t> Compress(const std::vector<uint8_t>& bytes, CompressionCodec::type compression) {
    if (compression == CompressionCodec::UNCOMPRESSED) {
        return bytes;
    }
    
    if (compression == CompressionCodec::SNAPPY) {
        if (bytes.empty()) {
            return bytes;
        }
        std::string compressed;
        snappy::Compress(reinterpret_cast<const char*>(bytes.data()), bytes.size(), &compressed);
        return std::vector<uint8_t>(compressed.begin(), compressed.end());
    }
    
    // Note for future implementations: If compression fails because of invalid or corrupt input,
    // then throw an InvalidInputException.
    throw DBPSUnsupportedException(
        "Unsupported compression codec: " + std::string(to_string(compression)));
}

std::vector<uint8_t> Decompress(const std::vector<uint8_t>& bytes, CompressionCodec::type compression) {
    if (compression == CompressionCodec::UNCOMPRESSED) {
        return bytes;
    }
    
    if (compression == CompressionCodec::SNAPPY) {
        if (bytes.empty()) {
            return bytes;
        }
        std::string decompressed;
        bool success = snappy::Uncompress(reinterpret_cast<const char*>(bytes.data()), bytes.size(), &decompressed);
        if (!success) {
            throw InvalidInputException("Failed to decompress data: invalid or corrupt Snappy-compressed input");
        }
        return std::vector<uint8_t>(decompressed.begin(), decompressed.end());
    }
    
    // Note for future implementations: If decompression fails because of invalid or corrupt input,
    // then throw an InvalidInputException.
    throw DBPSUnsupportedException(
        "Unsupported compression codec: " + std::string(to_string(compression)));
}

