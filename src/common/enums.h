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

namespace dbps::external {

// Captures the data type of the data batch elements.
// Intentionally similar to parquet::Type to ease mapping and for compatibility with a known enum.
// Originally defined in Arrow codebase: arrow/blob/main/cpp/src/parquet/types.h
struct Type {
    enum type {
        BOOLEAN = 0,
        INT32 = 1,
        INT64 = 2,
        INT96 = 3,
        FLOAT = 4,
        DOUBLE = 5,
        BYTE_ARRAY = 6,
        FIXED_LEN_BYTE_ARRAY = 7,
        UNDEFINED = 8
    };
};

// Intentionally similar to arrow::CompressionCodec
// Originally defined in Arrow codebase: //arrow/blob/main/cpp/src/arrow/util/type_fwd.h
struct CompressionCodec {
    enum type {
        UNCOMPRESSED = 0,
        SNAPPY = 1,
        GZIP = 2,
        BROTLI = 3,
        ZSTD = 4,
        LZ4 = 5,
        LZ4_FRAME = 6,
        LZO = 7,
        BZ2 = 8,
        LZ4_HADOOP = 9
    };
};

// Format for data values
// Intentionally similar to parquet::Encoding to ease mapping and for compatibility with a known enum.
// Originally defined in Arrow codebase: arrow/blob/main/cpp/src/parquet/types.h
// TODO: Rename to Encoding to match parquet::Encoding (as a further cleanup)
struct Format {
    enum type {
        PLAIN = 0,
        PLAIN_DICTIONARY = 2,
        RLE = 3,
        BIT_PACKED = 4,
        DELTA_BINARY_PACKED = 5,
        DELTA_LENGTH_BYTE_ARRAY = 6,
        DELTA_BYTE_ARRAY = 7,
        RLE_DICTIONARY = 8,
        BYTE_STREAM_SPLIT = 9,
        UNDEFINED = 10,
        UNKNOWN = 11
    };
};

}
