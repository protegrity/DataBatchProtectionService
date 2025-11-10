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

}
