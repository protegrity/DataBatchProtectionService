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

namespace dbps::compression {

std::vector<uint8_t> Compress(tcb::span<const uint8_t> bytes, CompressionCodec::type compression) {
    if (compression == CompressionCodec::UNCOMPRESSED) {
        return std::vector<uint8_t>(bytes.begin(), bytes.end());
    }
    
    if (compression == CompressionCodec::SNAPPY) {
        if (bytes.empty()) {
            return std::vector<uint8_t>();
        }
        std::vector<uint8_t> out_buffer;
        out_buffer.resize(snappy::MaxCompressedLength(bytes.size()));
        size_t compressed_size = 0;
        snappy::RawCompress(
            reinterpret_cast<const char*>(bytes.data()),
            bytes.size(),
            reinterpret_cast<char*>(out_buffer.data()),
            &compressed_size);
        out_buffer.resize(compressed_size);
        return out_buffer;
    }
    
    // Note for future implementations: If compression fails because of invalid or corrupt input,
    // then throw an InvalidInputException.
    throw DBPSUnsupportedException(
        "Unsupported compression codec: " + std::string(to_string(compression)));
}

std::vector<uint8_t> Decompress(tcb::span<const uint8_t> bytes, CompressionCodec::type compression) {
    if (compression == CompressionCodec::UNCOMPRESSED) {
        return std::vector<uint8_t>(bytes.begin(), bytes.end());
    }
    
    if (compression == CompressionCodec::SNAPPY) {
        if (bytes.empty()) {
            return std::vector<uint8_t>();
        }
        std::vector<uint8_t> out_buffer;
        size_t uncompressed_size = 0;
        if (!snappy::GetUncompressedLength(
                reinterpret_cast<const char*>(bytes.data()), bytes.size(), &uncompressed_size)) {
            throw InvalidInputException("Failed to decompress data: invalid or corrupt Snappy-compressed input");
        }
        out_buffer.resize(uncompressed_size);
        if (!snappy::RawUncompress(
                reinterpret_cast<const char*>(bytes.data()),
                bytes.size(),
                reinterpret_cast<char*>(out_buffer.data()))) {
            throw InvalidInputException("Failed to decompress data: invalid or corrupt Snappy-compressed input");
        }
        return out_buffer;
    }
    
    // Note for future implementations: If decompression fails because of invalid or corrupt input,
    // then throw an InvalidInputException.
    throw DBPSUnsupportedException(
        "Unsupported compression codec: " + std::string(to_string(compression)));
}

} // namespace dbps::compression
