#pragma once

#include <optional>
#include <string_view>

#include "enums.h"

namespace dbps::enum_utils {

// For dbps::external::Type
std::string_view to_string(::dbps::external::Type::type v);
std::optional<::dbps::external::Type::type> from_string_type(std::string_view s);

// For dbps::external::CompressionCodec
std::string_view to_string(::dbps::external::CompressionCodec::type v);
std::optional<::dbps::external::CompressionCodec::type> from_string_codec(std::string_view s);

// For dbps::external::Format
std::string_view to_string(::dbps::external::Format::type v);
std::optional<::dbps::external::Format::type> from_string_format(std::string_view s);

// For dbps::external::Encoding
std::string_view to_string(::dbps::external::Encoding::type v);
std::optional<::dbps::external::Encoding::type> from_string_encoding(std::string_view s);

}
