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

#include "typed_list_values.h"

#include <sstream>
#include <iomanip>
#include <type_traits>
#include <stdexcept>
#include <cstring>
#include "bytes_utils.h"

// Convert decrypted byte-vectors into a TypedListValues according to datatype
TypedListValues BuildTypedListFromRawBytes(
    Type::type datatype,
    const std::vector<RawValueBytes>& elements_bytes) {

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
        default:
            throw std::runtime_error("DecryptTypedListValues: unsupported datatype");
    }
}    

// helper function to build list of raw bytes from a TypedListValues
std::vector<RawValueBytes> BuildRawBytesFromTypedListValues(const TypedListValues& elements) {
    std::vector<RawValueBytes> raw_values;
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

        raw_values.reserve(vec.size());
        for (size_t i = 0; i < vec.size(); ++i) {
            const ElemT& elem = vec[i];
            std::vector<uint8_t> bytes = serialize(elem);
            raw_values.push_back(std::move(bytes));
        }
    }, elements);
    return raw_values;
}

namespace {

template<typename T>
const char* GetTypeName() {
    if constexpr (std::is_same_v<T, std::vector<int32_t>>) return "INT32";
    else if constexpr (std::is_same_v<T, std::vector<int64_t>>) return "INT64";
    else if constexpr (std::is_same_v<T, std::vector<float>>) return "FLOAT";
    else if constexpr (std::is_same_v<T, std::vector<double>>) return "DOUBLE";
    else if constexpr (std::is_same_v<T, std::vector<std::array<uint32_t, 3>>>) return "INT96";
    else if constexpr (std::is_same_v<T, std::vector<std::string>>) 
      return "string (BYTE_ARRAY/FIXED_LEN_BYTE_ARRAY)";
    else if constexpr (std::is_same_v<T, std::monostate>) return "empty/error";
    else return "unknown";
}

} // namespace

std::string TypedListToString(const TypedListValues& list) {
    std::ostringstream out;
    
    std::visit([&out](auto&& values) {
        using T = std::decay_t<decltype(values)>;
        
        if constexpr (std::is_same_v<T, std::monostate>) {
            out << "Empty/error state\n";
        }
        else if constexpr (std::is_same_v<T, std::vector<std::array<uint32_t, 3>>>) {
            // Special case for INT96 - [lo, mid, hi] format
            out << "Decoded INT96 values ([lo, mid, hi] 32-bit words):\n";
            for (size_t i = 0; i < values.size(); ++i) {
                out << "  [" << i << "] [" << values[i][0] << ", " 
                    << values[i][1] << ", " << values[i][2] << "]\n";
            }
        }
        else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
            // String values with quotes and the length of the string.
            out << "Decoded " << GetTypeName<T>() << " values:\n";
            for (size_t i = 0; i < values.size(); ++i) {
                out << "  [" << i << "] \"" << values[i] << "\" (length: " << values[i].size() << ")\n";
            }
        }
        else {
            // Generic case for numeric types (int32, int64, float, double)
            out << "Decoded " << GetTypeName<T>() << " values:\n";
            for (size_t i = 0; i < values.size(); ++i) {
                out << "  [" << i << "] " << values[i] << "\n";
            }
        }
    }, list);
    
    return out.str();
}

