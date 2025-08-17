#pragma once

#include <optional>
#include <string_view>

#include "enums.h"

namespace dbps::enum_utils {

// For dbps::external::Type
std::string_view to_string(::dbps::external::Type::type v);
std::optional<::dbps::external::Type::type> to_datatype_enum(std::string_view s);

// For dbps::external::CompressionCodec
std::string_view to_string(::dbps::external::CompressionCodec::type v);
std::optional<::dbps::external::CompressionCodec::type> to_compression_enum(std::string_view s);

// For dbps::external::Format
std::string_view to_string(::dbps::external::Format::type v);
std::optional<::dbps::external::Format::type> to_format_enum(std::string_view s);

// For dbps::external::Encoding
std::string_view to_string(::dbps::external::Encoding::type v);
std::optional<::dbps::external::Encoding::type> to_encoding_enum(std::string_view s);

}
