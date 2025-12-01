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

#include "value_encryption_utils.h"

#include <stdexcept>
#include <limits>
#include <cstring>
#include <string>
#include <array>
#include <variant>
#include <type_traits>

namespace { //file-local helper functions
    inline void append_u32_le(std::vector<uint8_t>& out, uint32_t v) {
        out.push_back(static_cast<uint8_t>(v & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    }

    inline uint32_t read_u32_le(const std::vector<uint8_t>& in, size_t offset) {
        return static_cast<uint32_t>(in[offset]) |
            (static_cast<uint32_t>(in[offset + 1]) << 8) |
            (static_cast<uint32_t>(in[offset + 2]) << 16) |
            (static_cast<uint32_t>(in[offset + 3]) << 24);
    }

    inline void append_i32_le(std::vector<uint8_t>& out, int32_t v) {
        append_u32_le(out, static_cast<uint32_t>(v));
    }

    inline void append_u64_le(std::vector<uint8_t>& out, uint64_t v) {
        out.push_back(static_cast<uint8_t>(v & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 32) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 40) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 48) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 56) & 0xFF));
    }

    inline void append_i64_le(std::vector<uint8_t>& out, int64_t v) {
        append_u64_le(out, static_cast<uint64_t>(v));
    }

    inline void append_f32_le(std::vector<uint8_t>& out, float v) {
        uint32_t bits = 0;
        std::memcpy(&bits, &v, sizeof(bits));
        append_u32_le(out, bits);
    }

    inline void append_f64_le(std::vector<uint8_t>& out, double v) {
        uint64_t bits = 0;
        std::memcpy(&bits, &v, sizeof(bits));
        append_u64_le(out, bits);
    }

    // Helper: Convert decrypted byte-vectors into a TypedListValues according to datatype
    TypedListValues BuildTypedListFromDecryptedBytes(
        Type::type datatype,
        const std::vector<std::vector<uint8_t> >& elements_bytes) {
        switch (datatype) {
            case Type::INT32: {
                std::vector<int32_t> out;
                for (size_t i = 0; i < elements_bytes.size(); ++i) {
                    const std::vector<uint8_t>& bytes = elements_bytes[i];
                    if (bytes.size() != 4) {
                        throw std::runtime_error("DecryptTypedListValues: invalid INT32 element size");
                    }
                    int32_t v = static_cast<int32_t>(bytes[0]) |
                                (static_cast<int32_t>(bytes[1]) << 8) |
                                (static_cast<int32_t>(bytes[2]) << 16) |
                                (static_cast<int32_t>(bytes[3]) << 24);
                    out.push_back(v);
                }
                return out;
            }
            case Type::INT64: {
                std::vector<int64_t> out;
                for (size_t i = 0; i < elements_bytes.size(); ++i) {
                    const std::vector<uint8_t>& bytes = elements_bytes[i];
                    if (bytes.size() != 8) {
                        throw std::runtime_error("DecryptTypedListValues: invalid INT64 element size");
                    }
                    uint64_t u = static_cast<uint64_t>(bytes[0]) |
                                 (static_cast<uint64_t>(bytes[1]) << 8) |
                                 (static_cast<uint64_t>(bytes[2]) << 16) |
                                 (static_cast<uint64_t>(bytes[3]) << 24) |
                                 (static_cast<uint64_t>(bytes[4]) << 32) |
                                 (static_cast<uint64_t>(bytes[5]) << 40) |
                                 (static_cast<uint64_t>(bytes[6]) << 48) |
                                 (static_cast<uint64_t>(bytes[7]) << 56);
                    out.push_back(static_cast<int64_t>(u));
                }
                return out;
            }
            case Type::FLOAT: {
                std::vector<float> out;
                for (size_t i = 0; i < elements_bytes.size(); ++i) {
                    const std::vector<uint8_t>& bytes = elements_bytes[i];
                    if (bytes.size() != 4) {
                        throw std::runtime_error("DecryptTypedListValues: invalid FLOAT element size");
                    }
                    uint32_t bits = static_cast<uint32_t>(bytes[0]) |
                                    (static_cast<uint32_t>(bytes[1]) << 8) |
                                    (static_cast<uint32_t>(bytes[2]) << 16) |
                                    (static_cast<uint32_t>(bytes[3]) << 24);
                    float v;
                    std::memcpy(&v, &bits, sizeof(v));
                    out.push_back(v);
                }
                return out;
            }
            case Type::DOUBLE: {
                std::vector<double> out;
                for (size_t i = 0; i < elements_bytes.size(); ++i) {
                    const std::vector<uint8_t>& bytes = elements_bytes[i];
                    if (bytes.size() != 8) {
                        throw std::runtime_error("DecryptTypedListValues: invalid DOUBLE element size");
                    }
                    uint64_t bits = static_cast<uint64_t>(bytes[0]) |
                                    (static_cast<uint64_t>(bytes[1]) << 8) |
                                    (static_cast<uint64_t>(bytes[2]) << 16) |
                                    (static_cast<uint64_t>(bytes[3]) << 24) |
                                    (static_cast<uint64_t>(bytes[4]) << 32) |
                                    (static_cast<uint64_t>(bytes[5]) << 40) |
                                    (static_cast<uint64_t>(bytes[6]) << 48) |
                                    (static_cast<uint64_t>(bytes[7]) << 56);
                    double v;
                    std::memcpy(&v, &bits, sizeof(v));
                    out.push_back(v);
                }
                return out;
            }
            case Type::INT96: {
                std::vector<std::array<uint32_t, 3> > out;
                for (size_t i = 0; i < elements_bytes.size(); ++i) {
                    const std::vector<uint8_t>& bytes = elements_bytes[i];
                    if (bytes.size() != 12) {
                        throw std::runtime_error("DecryptTypedListValues: invalid INT96 element size");
                    }
                    std::array<uint32_t, 3> a;
                    a[0] = static_cast<uint32_t>(bytes[0]) |
                           (static_cast<uint32_t>(bytes[1]) << 8) |
                           (static_cast<uint32_t>(bytes[2]) << 16) |
                           (static_cast<uint32_t>(bytes[3]) << 24);
                    a[1] = static_cast<uint32_t>(bytes[4]) |
                           (static_cast<uint32_t>(bytes[5]) << 8) |
                           (static_cast<uint32_t>(bytes[6]) << 16) |
                           (static_cast<uint32_t>(bytes[7]) << 24);
                    a[2] = static_cast<uint32_t>(bytes[8]) |
                           (static_cast<uint32_t>(bytes[9]) << 8) |
                           (static_cast<uint32_t>(bytes[10]) << 16) |
                           (static_cast<uint32_t>(bytes[11]) << 24);
                    out.push_back(a);
                }
                return out;
            }
            case Type::BYTE_ARRAY:
            case Type::FIXED_LEN_BYTE_ARRAY: {
                std::vector<std::string> out;
                for (size_t i = 0; i < elements_bytes.size(); ++i) {
                    const std::vector<uint8_t>& bytes = elements_bytes[i];
                    out.emplace_back(reinterpret_cast<const char*>(bytes.data()), bytes.size());
                }
                return out;
            }
            case Type::UNDEFINED: {
                std::vector<uint8_t> out;
                for (size_t i = 0; i < elements_bytes.size(); ++i) {
                    const std::vector<uint8_t>& bytes = elements_bytes[i];
                    if (bytes.size() != 1) {
                        throw std::runtime_error("DecryptTypedListValues: invalid UNDEFINED element size");
                    }
                    out.push_back(bytes[0]);
                }
                return out;
            }
            default:
                throw std::runtime_error("DecryptTypedListValues: unsupported datatype");
        }
    }
} // namespace (anon)

namespace dbps::value_encryption_utils {

std::vector<uint8_t> ConcatenateEncryptedValues(const std::vector<EncryptedValue>& values) {
    if (values.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        throw std::overflow_error("Too many elements to serialize into uint32 count");
    }

    // Precompute capacity: 4 bytes for count + for each element (4 bytes size + payload)
    size_t total_capacity = 4;
    for (size_t i = 0; i < values.size(); ++i) {
        const EncryptedValue& ev = values[i];
        if (ev.size > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
            throw std::overflow_error("Element size exceeds uint32 capacity");
        }
        if (ev.payload.size() < ev.size) {
            throw std::runtime_error("ConcatenateEncryptedValues: payload smaller than declared size");
        }
        total_capacity += 4 + ev.size;
    }

    std::vector<uint8_t> out;
    out.reserve(total_capacity);

    append_u32_le(out, static_cast<uint32_t>(values.size()));

    for (size_t i = 0; i < values.size(); ++i) {
        const EncryptedValue& ev = values[i];
        append_u32_le(out, static_cast<uint32_t>(ev.size));
        // Append exactly 'size' bytes; prevalidated that payload.size() >= size
        out.insert(out.end(), ev.payload.begin(), ev.payload.begin() + ev.size);
    }

    return out;
}

std::vector<EncryptedValue> ParseConcatenatedEncryptedValues(const std::vector<uint8_t>& blob) {
    size_t offset = 0;
    if (blob.size() < 4) {
        throw std::runtime_error("Malformed input: missing element count");
    }
    uint32_t count = read_u32_le(blob, offset);
    offset += 4;

    std::vector<EncryptedValue> result;
    result.reserve(static_cast<size_t>(count));

    for (uint32_t i = 0; i < count; ++i) {
        if (blob.size() - offset < 4) {
            throw std::runtime_error("Malformed input: truncated size field");
        }
        uint32_t sz = read_u32_le(blob, offset);
        offset += 4;

        if (blob.size() - offset < static_cast<size_t>(sz)) {
            throw std::runtime_error("Malformed input: truncated payload bytes");
        }

        EncryptedValue ev;
        ev.size = static_cast<size_t>(sz);
        ev.payload.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                          blob.begin() + static_cast<std::ptrdiff_t>(offset + ev.size));
        offset += ev.size;
        result.push_back(std::move(ev));
    }

    // ensure no trailing bytes remain after parsing
    if (offset != blob.size()) {
        throw std::runtime_error("Malformed input: trailing bytes after parsing EncryptedValue entries");
    }
    return result;
}

EncryptedValue EncryptValue(const std::vector<uint8_t>& value, const std::vector<uint8_t>& key) {
    EncryptedValue ev;
    if (value.empty()) {
        ev.size = 0;
        return ev;
    }
    if (key.empty()) {
        throw std::invalid_argument("EncryptValue: key must not be empty for non-empty input");
    }
    ev.size = value.size();
    ev.payload.resize(ev.size);
    size_t key_index = 0;
    const size_t key_len = key.size();
    for (size_t i = 0; i < ev.size; ++i) {
        ev.payload[i] = static_cast<uint8_t>(value[i] ^ key[key_index]);
        key_index = (key_index + 1) % key_len; // rotate one key byte at a time
    }
    return ev;
}

std::vector<uint8_t> DecryptValue(const EncryptedValue& value, const std::vector<uint8_t>& key) {
    if (value.size == 0) {
        return std::vector<uint8_t>();
    }
    if (key.empty()) {
        throw std::invalid_argument("DecryptValue: key must not be empty for non-empty input");
    }
    const size_t bytes_to_process = value.size <= value.payload.size() ? value.size : value.payload.size();
    std::vector<uint8_t> out(bytes_to_process);
    size_t key_index = 0;
    const size_t key_len = key.size();
    for (size_t i = 0; i < bytes_to_process; ++i) {
        out[i] = static_cast<uint8_t>(value.payload[i] ^ key[key_index]);
        key_index = (key_index + 1) % key_len;
    }
    return out;
}

std::vector<uint8_t> ConcatenateBuffersWithLength(const std::vector<std::vector<uint8_t> >& buffers) {
    // Precompute capacity and validate sizes
    size_t total_capacity = 0;
    for (size_t i = 0; i < buffers.size(); ++i) {
        const std::vector<uint8_t>& buf = buffers[i];
        if (buf.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
            throw std::overflow_error("Buffer size exceeds uint32 capacity");
        }
        total_capacity += 4 + buf.size();
    }

    std::vector<uint8_t> out;
    out.reserve(total_capacity);
    for (size_t i = 0; i < buffers.size(); ++i) {
        const std::vector<uint8_t>& buf = buffers[i];
        append_u32_le(out, static_cast<uint32_t>(buf.size()));
        out.insert(out.end(), buf.begin(), buf.end());
    }
    return out;
}

std::vector<std::vector<uint8_t> > ParseBuffersWithLength(const std::vector<uint8_t>& blob) {
    std::vector<std::vector<uint8_t> > buffers;
    size_t offset = 0;
    while (offset < blob.size()) {
        if (blob.size() - offset < 4) {
            throw std::runtime_error("Malformed input: truncated size field in buffers blob");
        }
        uint32_t sz = read_u32_le(blob, offset);
        offset += 4;
        if (blob.size() - offset < static_cast<size_t>(sz)) {
            throw std::runtime_error("Malformed input: truncated buffer payload in buffers blob");
        }
        std::vector<uint8_t> buf;
        if (sz > 0) {
            buf.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                       blob.begin() + static_cast<std::ptrdiff_t>(offset + sz));
        }
        offset += sz;
        buffers.push_back(std::move(buf));
    }
    // Strict: offset must equal blob.size()
    if (offset != blob.size()) {
        throw std::runtime_error("Malformed input: trailing bytes after parsing buffers");
    }
    return buffers;
}

// TODO: find better name?
std::vector<uint8_t> EncryptTypedListValues(
    const TypedListValues& elements,
    const std::vector<uint8_t>& key) {
    std::vector<EncryptedValue> encrypted_elements;

    std::visit([&](const auto& vec) {
        typedef std::decay_t<decltype(vec)> VecT;
        typedef typename VecT::value_type ElemT;

        auto serialize = [&](const ElemT& elem) -> std::vector<uint8_t> {
            std::vector<uint8_t> serialized;
            if constexpr (std::is_same<ElemT, int32_t>::value) {
                append_i32_le(serialized, elem);
            } else if constexpr (std::is_same<ElemT, int64_t>::value) {
                append_i64_le(serialized, elem);
            } else if constexpr (std::is_same<ElemT, float>::value) {
                append_f32_le(serialized, elem);
            } else if constexpr (std::is_same<ElemT, double>::value) {
                append_f64_le(serialized, elem);
            } else if constexpr (std::is_same<ElemT, std::array<uint32_t, 3> >::value) {
                append_u32_le(serialized, elem[0]);
                append_u32_le(serialized, elem[1]);
                append_u32_le(serialized, elem[2]);
            } else if constexpr (std::is_same<ElemT, std::string>::value) {
                serialized.insert(serialized.end(), elem.begin(), elem.end());
            } else if constexpr (std::is_same<ElemT, uint8_t>::value) {
                serialized.push_back(elem);
            } else {
                static_assert(sizeof(ElemT) == 0, "Unsupported element type in TypedListValues");
            }
            return serialized;
        };

        for (size_t i = 0; i < vec.size(); ++i) {
            const ElemT& elem = vec[i];
            std::vector<uint8_t> bytes = serialize(elem);
            encrypted_elements.push_back(EncryptValue(bytes, key));
        }
    }, elements);

    return ConcatenateEncryptedValues(encrypted_elements);
}

// Inverse of EncryptTypedListValues - high-level orchestration
TypedListValues DecryptTypedListValues(
    const std::vector<uint8_t>& blob,
    Type::type datatype,
    const std::vector<uint8_t>& key) {
    // 1) Parse into EncryptedValue elements
    std::vector<EncryptedValue> encrypted_values = ParseConcatenatedEncryptedValues(blob);
    // 2) Decrypt each element into its raw bytes
    std::vector<std::vector<uint8_t> > decrypted_bytes;
    decrypted_bytes.reserve(encrypted_values.size());
    for (size_t i = 0; i < encrypted_values.size(); ++i) {
        decrypted_bytes.push_back(DecryptValue(encrypted_values[i], key));
    }
    // 3) Convert all decrypted bytes to a TypedListValues according to datatype
    return BuildTypedListFromDecryptedBytes(datatype, decrypted_bytes);
}

std::vector<uint8_t> EncryptTypedListValuesWithLevelBytes(
    const TypedListValues& elements,
    const std::vector<uint8_t>& level_bytes,
    const std::vector<uint8_t>& key) {

    std::vector<uint8_t> encrypted_values = EncryptTypedListValues(elements, key);

    //let's concatenate the encrypted values with the level bytes.
    // encrypted values first, then level bytes.
    std::vector<std::vector<uint8_t> > buffers;
    buffers.push_back(encrypted_values);
    buffers.push_back(level_bytes);

    return ConcatenateBuffersWithLength(buffers);
}

std::pair<TypedListValues, std::vector<uint8_t> > DecryptTypedListValuesWithLevelBytes(
    const std::vector<uint8_t>& combined_blob,
    Type::type datatype,
    const std::vector<uint8_t>& key) {
    // Expect exactly two buffers: [encrypted_values_blob, level_bytes]
    std::vector<std::vector<uint8_t> > buffers = ParseBuffersWithLength(combined_blob);
    if (buffers.size() != 2u) {
        throw std::runtime_error("DecryptTypedListValuesWithLevelBytes: expected two buffers");
    }

    // at encode/encrypt time, we put together two blobs:
    // first the encrypted values, then the level bytes.
    // we now need to split them back into the two blobs.
    const std::vector<uint8_t>& encrypted_values_blob = buffers[0];
    const std::vector<uint8_t>& level_bytes = buffers[1];

    TypedListValues values = DecryptTypedListValues(encrypted_values_blob, datatype, key);
    return std::make_pair(values, level_bytes);
}

} // namespace dbps::value_encryption_utils
