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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>
#include <cxxopts.hpp>

#include "../common/dbpa_local.h"
#include "../common/enums.h"
#include "../common/enum_utils.h"
#include "../common/bytes_utils.h"
#include "../processing/compression_utils.h"
#include "../processing/parquet_utils.h"
#include "tcb/span.hpp"

using namespace dbps::external;
using namespace dbps::enum_utils;
using namespace dbps::compression;

template <typename T>
using span = tcb::span<T>;

namespace {
    std::vector<uint8_t> MakeByteArrayListPayload(const std::vector<std::string>& items) {
        std::vector<RawValueBytes> elements;
        elements.reserve(items.size());
        for (const auto& s : items) {
            elements.emplace_back(s.begin(), s.end());
        }
        return CombineRawBytesIntoValueBytes(
            elements, Type::BYTE_ARRAY, std::nullopt, Encoding::PLAIN);
    }

    std::vector<uint8_t> BuildFloatValueBytes(const std::vector<std::string>& values) {
        std::vector<uint8_t> bytes;
        bytes.reserve(values.size() * sizeof(float));
        for (const auto& value : values) {
            append_f32_le(bytes, std::stof(value));
        }
        return bytes;
    }

    std::vector<uint8_t> BuildInt32ValueBytes(const std::vector<std::string>& values) {
        std::vector<uint8_t> bytes;
        bytes.reserve(values.size() * sizeof(int32_t));
        for (const auto& value : values) {
            append_i32_le(bytes, static_cast<int32_t>(std::stol(value)));
        }
        return bytes;
    }

    std::vector<uint8_t> BuildInt64ValueBytes(const std::vector<std::string>& values) {
        std::vector<uint8_t> bytes;
        bytes.reserve(values.size() * sizeof(int64_t));
        for (const auto& value : values) {
            append_i64_le(bytes, static_cast<int64_t>(std::stoll(value)));
        }
        return bytes;
    }

    std::vector<std::string> ReadLines(const std::string& path, std::optional<size_t> max_rows) {
        auto try_open = [](const std::filesystem::path& candidate) -> std::ifstream {
            std::ifstream file(candidate);
            return file;
        };

        std::filesystem::path input_path(path);
        std::vector<std::filesystem::path> attempts;
        attempts.push_back(input_path);
        std::ifstream file = try_open(input_path);
        if (!file.is_open() && input_path.is_relative()) {
            std::filesystem::path source_dir = std::filesystem::path(__FILE__).parent_path();
            std::filesystem::path alt_path = source_dir / input_path;
            attempts.push_back(alt_path);
            file = try_open(alt_path);
        }
        if (!file.is_open()) {
            std::ostringstream oss;
            oss << "Failed to open values file. Tried:";
            for (const auto& attempt : attempts) {
                oss << " " << attempt.string();
            }
            throw std::runtime_error(oss.str());
        }

        std::vector<std::string> lines;
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                lines.push_back(line);
                if (max_rows.has_value() && lines.size() >= max_rows.value()) {
                    break;
                }
            }
        }
        return lines;
    }

    struct DataPageBuildResult {
        std::vector<uint8_t> payload;
        std::map<std::string, std::string> attrs;
        std::vector<uint8_t> level_bytes;
        int32_t def_levels_byte_length = 0;
        int32_t rep_levels_byte_length = 0;
    };

    DataPageBuildResult BuildDataPageV2Payload(
        const std::vector<uint8_t>& value_bytes,
        size_t num_values,
        CompressionCodec::type compression_type,
        const std::string& page_encoding,
        int32_t max_definition_level = 1,
        int32_t max_repetition_level = 0,
        int32_t definition_levels_byte_length = 2,
        int32_t repetition_levels_byte_length = 1,
        int32_t num_nulls = 0,
        bool is_compressed = true) {
        DataPageBuildResult result;
        result.def_levels_byte_length = definition_levels_byte_length;
        result.rep_levels_byte_length = repetition_levels_byte_length;
        result.level_bytes = std::vector<uint8_t>(
            static_cast<size_t>(definition_levels_byte_length + repetition_levels_byte_length), 0x00);

        std::vector<uint8_t> value_payload = value_bytes;
        if (is_compressed) {
            value_payload = Compress(value_bytes, compression_type);
        }
        result.payload = Join(result.level_bytes, value_payload);

        result.attrs = {
            {"page_type", "DATA_PAGE_V2"},
            {"data_page_num_values", std::to_string(num_values)},
            {"data_page_max_definition_level", std::to_string(max_definition_level)},
            {"data_page_max_repetition_level", std::to_string(max_repetition_level)},
            {"page_v2_definition_levels_byte_length", std::to_string(definition_levels_byte_length)},
            {"page_v2_repetition_levels_byte_length", std::to_string(repetition_levels_byte_length)},
            {"page_v2_num_nulls", std::to_string(num_nulls)},
            {"page_v2_is_compressed", is_compressed ? "true" : "false"},
            {"page_encoding", page_encoding}
        };

        return result;
    }

    DataPageBuildResult BuildDataPageV1Payload(
        const std::vector<uint8_t>& value_bytes,
        size_t num_values,
        CompressionCodec::type compression_type,
        const std::string& page_encoding,
        int32_t max_definition_level = 1,
        int32_t max_repetition_level = 1,
        uint32_t repetition_level_block_length = 1,
        uint32_t definition_level_block_length = 2) {
        DataPageBuildResult result;
        result.level_bytes.clear();
        append_u32_le(result.level_bytes, repetition_level_block_length); // repetition level block length
        result.level_bytes.push_back(0xAA);
        append_u32_le(result.level_bytes, definition_level_block_length); // definition level block length
        result.level_bytes.push_back(0xBB);
        result.level_bytes.push_back(0xCC);
        auto combined_uncompressed = Join(result.level_bytes, value_bytes);
        result.payload = Compress(combined_uncompressed, compression_type);
        result.attrs = {
            {"page_type", "DATA_PAGE_V1"},
            {"data_page_num_values", std::to_string(num_values)},
            {"data_page_max_repetition_level", std::to_string(max_repetition_level)},
            {"data_page_max_definition_level", std::to_string(max_definition_level)},
            {"page_v1_repetition_level_encoding", "RLE"},
            {"page_v1_definition_level_encoding", "RLE"},
            {"page_encoding", page_encoding}
        };

        return result;
    }

    DataPageBuildResult BuildDictionaryPagePayload(
        const std::vector<uint8_t>& value_bytes,
        CompressionCodec::type compression_type,
        const std::string& page_encoding) {
        DataPageBuildResult result;
        result.level_bytes.clear();
        result.payload = Compress(value_bytes, compression_type);
        result.attrs = {
            {"page_type", "DICTIONARY_PAGE"},
            {"page_encoding", page_encoding}
        };
        return result;
    }

    std::unique_ptr<LocalDataBatchProtectionAgent> BuildLocalDbpaAgent(
        CompressionCodec::type compression_type,
        Type::type datatype,
        std::optional<int> datatype_length,
        std::optional<std::map<std::string, std::string>> column_encryption_metadata = std::nullopt) {
        std::string app_context = R"({"user_id": "demo_user_123"})";
        auto agent = std::make_unique<LocalDataBatchProtectionAgent>();

        agent->init(
            "local_demo_column",             // column_name
            {},                              // configuration_map
            app_context,                     // app_context
            "local_demo_key_001",            // column_key_id
            datatype,                        // datatype
            datatype_length,                 // datatype_length
            compression_type,                // compression_type
            column_encryption_metadata       // column_encryption_metadata
        );

        return agent;
    }

    struct Scenario {
        std::string name;
        std::string page_type;
        CompressionCodec::type compression;
        std::string page_encoding;
    };

    const std::vector<Scenario> kScenarios = {
        {"data_page_v1, compression=None, encoding=PLAIN", "DATA_PAGE_V1", CompressionCodec::UNCOMPRESSED, "PLAIN"},
        {"dictionary_page, compression=SNAPPY, encoding=PLAIN", "DICTIONARY_PAGE", CompressionCodec::SNAPPY, "PLAIN"},
        {"dictionary_page, compression=None, encoding=PLAIN", "DICTIONARY_PAGE", CompressionCodec::UNCOMPRESSED, "PLAIN"},
        {"data_page_v1, compression=SNAPPY, encoding=PLAIN", "DATA_PAGE_V1", CompressionCodec::SNAPPY, "PLAIN"},
        {"data_page_v2, compression=SNAPPY, encoding=PLAIN", "DATA_PAGE_V2", CompressionCodec::SNAPPY, "PLAIN"},
        {"data_page_v1, compression=None, encoding=RLE_DICTIONARY", "DATA_PAGE_V1", CompressionCodec::UNCOMPRESSED, "RLE_DICTIONARY"}
    };
}

class DBPALocalTestApp {
public:
    DBPALocalTestApp() {
        std::cout << "DBPA Local Performance Test" << std::endl;
        std::cout << "===========================" << std::endl;
        std::cout << std::endl;
    }

    bool TestLocalDbpaAgentScenarios(
        int scenario_number,
        Type::type datatype,
        const std::vector<uint8_t>& value_bytes,
        size_t num_values,
        std::optional<int> datatype_length) {
        std::cout << "\n=== Local DBPA Agent Scenarios ===" << std::endl;

        if (scenario_number <= 0 || scenario_number > static_cast<int>(kScenarios.size())) {
            std::cout << "ERROR: Invalid scenario number: " << scenario_number << std::endl;
            return false;
        }

        const auto& scenario = kScenarios[static_cast<size_t>(scenario_number - 1)];
        std::cout << "\nScenario: " << scenario.name
                  << " | datatype=" << to_string(datatype) << std::endl;

        DataPageBuildResult page;
        if (scenario.page_type == "DATA_PAGE_V1") {
            page = BuildDataPageV1Payload(
                value_bytes,
                num_values,
                scenario.compression,
                scenario.page_encoding);
        } else if (scenario.page_type == "DATA_PAGE_V2") {
            page = BuildDataPageV2Payload(
                value_bytes,
                num_values,
                scenario.compression,
                scenario.page_encoding);
        } else if (scenario.page_type == "DICTIONARY_PAGE") {
            page = BuildDictionaryPagePayload(
                value_bytes,
                scenario.compression,
                scenario.page_encoding);
        } else {
            std::cout << "  ERROR: Unknown page type: " << scenario.page_type << std::endl;
            return false;
        }

        auto encrypt_agent = BuildLocalDbpaAgent(
            scenario.compression,
            datatype,
            datatype_length);
        auto encrypt_result = encrypt_agent->Encrypt(span<const uint8_t>(page.payload), page.attrs);
        if (!encrypt_result || !encrypt_result->success()) {
            std::cout << "  ERROR: Encryption failed" << std::endl;
            if (encrypt_result) {
                std::cout << "    Error: " << encrypt_result->error_message() << std::endl;
            }
            return false;
        }

        auto encryption_metadata = encrypt_result->encryption_metadata();
        if (!encryption_metadata) {
            std::cout << "  ERROR: Missing encryption metadata" << std::endl;
            return false;
        }
        const std::string mode_key = (scenario.page_type == "DICTIONARY_PAGE")
            ? "encrypt_mode_dict_page"
            : "encrypt_mode_data_page";
        auto mode_it = encryption_metadata->find(mode_key);
        if (mode_it == encryption_metadata->end()) {
            std::cout << "  ERROR: Missing " << mode_key << " in encryption metadata" << std::endl;
            return false;
        }
        std::cout << "  Encryption mode: " << mode_it->second << std::endl;

        auto decrypt_agent = BuildLocalDbpaAgent(
            scenario.compression,
            datatype,
            datatype_length,
            encryption_metadata);
        auto decrypt_result = decrypt_agent->Decrypt(
            span<const uint8_t>(encrypt_result->ciphertext()),
            page.attrs);
        if (!decrypt_result || !decrypt_result->success()) {
            std::cout << "  ERROR: Decryption failed" << std::endl;
            if (decrypt_result) {
                std::cout << "    Error: " << decrypt_result->error_message() << std::endl;
            }
            return false;
        }

        auto decrypted_plaintext = decrypt_result->plaintext();
        if (decrypted_plaintext.size() != page.payload.size() ||
            !std::equal(decrypted_plaintext.begin(), decrypted_plaintext.end(), page.payload.begin())) {
            std::cout << "  ERROR: Round-trip payload mismatch" << std::endl;
            return false;
        }

        std::cout << "  OK: Encrypt/decrypt round-trip succeeded" << std::endl;
        return true;
    }

    void RunDemo(
        int scenario_number,
        Type::type datatype,
        const std::string& values_file_path,
        std::optional<size_t> max_rows) {
        std::cout << "Starting DBPA Local Performance Test..." << std::endl;
        std::cout << std::endl;
        std::cout << "\n--- Local DBPA Scenario ---" << std::endl;
        std::vector<std::string> lines = ReadLines(values_file_path, max_rows);
        if (lines.empty()) {
            std::cout << "ERROR: Values file is empty: " << values_file_path << std::endl;
            std::cout << "\n=== Demo Summary ===" << std::endl;
            std::cout << "Local DBPA Scenarios: FAIL" << std::endl;
            return;
        }

        std::vector<uint8_t> value_bytes;
        size_t num_values = 0;
        if (datatype == Type::BYTE_ARRAY) {
            num_values = lines.size();
            value_bytes = MakeByteArrayListPayload(lines);
        } else if (datatype == Type::FLOAT) {
            num_values = lines.size();
            value_bytes = BuildFloatValueBytes(lines);
        } else if (datatype == Type::INT32) {
            num_values = lines.size();
            value_bytes = BuildInt32ValueBytes(lines);
        } else if (datatype == Type::INT64) {
            num_values = lines.size();
            value_bytes = BuildInt64ValueBytes(lines);
        } else {
            std::cout << "ERROR: Unsupported datatype for values file: " << to_string(datatype) << std::endl;
            std::cout << "\n=== Demo Summary ===" << std::endl;
            std::cout << "Local DBPA Scenarios: FAIL" << std::endl;
            return;
        }

        bool local_dbpa_ok = TestLocalDbpaAgentScenarios(
            scenario_number,
            datatype,
            value_bytes,
            num_values,
            std::nullopt);

        std::cout << "\n=== Demo Summary ===" << std::endl;
        const auto& scenario = kScenarios[static_cast<size_t>(scenario_number - 1)];
        std::cout << "Scenario: " << scenario.name << " (#" << scenario_number << ")" << std::endl;
        std::cout << "Datatype: " << to_string(datatype) << std::endl;
        std::cout << "Values file: " << values_file_path << std::endl;
        std::cout << "Rows read: " << num_values << std::endl;
        std::cout << "Local DBPA Scenarios: " << (local_dbpa_ok ? "PASS" : "FAIL") << std::endl;
    }
};

int main(int argc, char* argv[]) {
    cxxopts::Options options("performance_test", "DBPA Local Performance Test");

    options.add_options()
        ("scenario_number", "Local DBPA scenario number (1-N).",
            cxxopts::value<int>()->default_value("1"))
        ("datatype", "Datatype to test (BYTE_ARRAY, FLOAT, INT32, INT64).",
            cxxopts::value<std::string>()->default_value("BYTE_ARRAY"))
        ("values_file", "Path to text file with one value per line.",
            cxxopts::value<std::string>())
        ("max_rows", "Maximum number of rows to read from values_file (0 = no limit).",
            cxxopts::value<size_t>()->default_value("0"))
        ("h,help", "Display this help message");

    try {
        auto result = options.parse(argc, argv);
        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            return 0;
        }

        int scenario_number = result["scenario_number"].as<int>();
        std::string datatype_arg = result["datatype"].as<std::string>();
        std::string values_file_path = result["values_file"].as<std::string>();
        size_t max_rows_raw = result["max_rows"].as<size_t>();

        if (values_file_path.empty()) {
            std::cout << "Error: --values_file is required." << std::endl;
            std::cout << options.help() << std::endl;
            return 1;
        }

        auto datatype_opt = to_datatype_enum(datatype_arg);
        if (!datatype_opt.has_value()) {
            std::cout << "Error: Unknown datatype: " << datatype_arg << std::endl;
            std::cout << options.help() << std::endl;
            return 1;
        }

        std::optional<size_t> max_rows;
        if (max_rows_raw > 0) {
            max_rows = max_rows_raw;
        }

        DBPALocalTestApp demo;
        demo.RunDemo(scenario_number, datatype_opt.value(), values_file_path, max_rows);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        std::cout << options.help() << std::endl;
        return 1;
    }
}
