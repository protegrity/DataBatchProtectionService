#include "enum_utils.h"

#include <array>
#include <optional>
#include <string_view>
#include <utility>

namespace dbps::enum_utils {

// Helper functions for converting between enum values and strings
namespace lookup {

template <typename E, std::size_t N>
constexpr std::string_view to_string_impl(
    E v,
    const std::array<std::pair<E, std::string_view>, N>& pairs) {
    for (auto&& [k, s] : pairs) {
        if (k == v) return s;
    }
    return "UNKNOWN_ENUM";
}

template <typename E, std::size_t N>
constexpr std::optional<E> from_string_impl(
    std::string_view s,
    const std::array<std::pair<E, std::string_view>, N>& pairs) {
    for (auto&& [k, name] : pairs) {
        if (name == s) return k;
    }
    return std::nullopt;
}

}

// For dbps::external::Type
namespace {
using T = ::dbps::external::Type::type;
inline constexpr std::array<std::pair<T, std::string_view>, 9> kTypePairs{{
    {T::BOOLEAN, "BOOLEAN"},
    {T::INT32, "INT32"},
    {T::INT64, "INT64"},
    {T::INT96, "INT96"},
    {T::FLOAT, "FLOAT"},
    {T::DOUBLE, "DOUBLE"},
    {T::BYTE_ARRAY, "BYTE_ARRAY"},
    {T::FIXED_LEN_BYTE_ARRAY, "FIXED_LEN_BYTE_ARRAY"},
    {T::UNDEFINED, "UNDEFINED"},
}};
} // anon

std::string_view to_string(T v) {
    return lookup::to_string_impl(v, kTypePairs);
}
std::optional<T> to_datatype_enum(std::string_view s) {
    return lookup::from_string_impl<T>(s, kTypePairs);
}

// For dbps::external::CompressionCodec
namespace {
using C = ::dbps::external::CompressionCodec::type;
inline constexpr std::array<std::pair<C, std::string_view>, 10> kCodecPairs{{
    {C::UNCOMPRESSED, "UNCOMPRESSED"},
    {C::SNAPPY, "SNAPPY"},
    {C::GZIP, "GZIP"},
    {C::BROTLI, "BROTLI"},
    {C::ZSTD, "ZSTD"},
    {C::LZ4, "LZ4"},
    {C::LZ4_FRAME, "LZ4_FRAME"},
    {C::LZO, "LZO"},
    {C::BZ2, "BZ2"},
    {C::LZ4_HADOOP, "LZ4_HADOOP"},
}};
} // anon

std::string_view to_string(C v) {
    return lookup::to_string_impl(v, kCodecPairs);
}
std::optional<C> to_compression_enum(std::string_view s) {
    return lookup::from_string_impl<C>(s, kCodecPairs);
}

// For dbps::external::Format
namespace {
using F = ::dbps::external::Format::type;
inline constexpr std::array<std::pair<F, std::string_view>, 11> kFormatPairs{{
    {F::PLAIN, "PLAIN"},
    {F::PLAIN_DICTIONARY, "PLAIN_DICTIONARY"},
    {F::RLE, "RLE"},
    {F::BIT_PACKED, "BIT_PACKED"},
    {F::DELTA_BINARY_PACKED, "DELTA_BINARY_PACKED"},
    {F::DELTA_LENGTH_BYTE_ARRAY, "DELTA_LENGTH_BYTE_ARRAY"},
    {F::DELTA_BYTE_ARRAY, "DELTA_BYTE_ARRAY"},
    {F::RLE_DICTIONARY, "RLE_DICTIONARY"},
    {F::BYTE_STREAM_SPLIT, "BYTE_STREAM_SPLIT"},
    {F::UNDEFINED, "UNDEFINED"},
    {F::UNKNOWN, "UNKNOWN"},
}};
} // anon

std::string_view to_string(F v) {
    return lookup::to_string_impl(v, kFormatPairs);
}
std::optional<F> to_format_enum(std::string_view s) {
    return lookup::from_string_impl<F>(s, kFormatPairs);
}

}
