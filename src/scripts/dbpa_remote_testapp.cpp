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

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <cxxopts.hpp>

// Include the necessary headers from the project
#include "../common/dbpa_remote.h"
#include "../client/httplib_client.h"
#include "../common/enums.h"
#include "../server/compression_utils.h"
#include "../common/bytes_utils.h"
#include "tcb/span.hpp"

using namespace dbps::external;
using namespace dbps::enum_utils;
using namespace dbps::compression;

template <typename T>
using span = tcb::span<T>;

namespace {
    const std::string SEQUENCER_ENCRYPTION_METADATA_VERSION = "v0.01";

    std::vector<uint8_t> MakeByteArrayPayload(const std::string& s) {
        std::vector<uint8_t> out;
        append_u32_le(out, static_cast<uint32_t>(s.size()));
        out.insert(out.end(), s.begin(), s.end());
        return out;
    }

    std::string ParseByteArrayPayload(const std::vector<uint8_t>& bytes) {
        if (bytes.size() < 4) {
            throw std::runtime_error("Invalid BYTE_ARRAY payload: too short for length prefix");
        }
        uint32_t len = read_u32_le(bytes, 0);
        if (bytes.size() != 4 + len) {
            throw std::runtime_error("Invalid BYTE_ARRAY payload: length mismatch");
        }
        return std::string(bytes.begin() + 4, bytes.end());
    }

    std::vector<uint8_t> MakeByteArrayListPayload(const std::vector<std::string>& items) {
        std::vector<uint8_t> out;
        size_t total = 0;
        for (const auto& s : items) {
            total += 4 + s.size();
        }
        out.reserve(total);
        for (const auto& s : items) {
            append_u32_le(out, static_cast<uint32_t>(s.size()));
            out.insert(out.end(), s.begin(), s.end());
        }
        return out;
    }

    std::vector<std::string> ParseByteArrayListPayload(const std::vector<uint8_t>& bytes) {
        std::vector<std::string> out;
        size_t offset = 0;
        while (offset < bytes.size()) {
            if (offset + 4 > bytes.size()) {
                throw std::runtime_error("Invalid BYTE_ARRAY list: incomplete length prefix");
            }
            uint32_t len = read_u32_le(bytes, static_cast<int>(offset));
            offset += 4;
            if (offset + len > bytes.size()) {
                throw std::runtime_error("Invalid BYTE_ARRAY list: length exceeds remaining data");
            }
            out.emplace_back(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                             bytes.begin() + static_cast<std::ptrdiff_t>(offset + len));
            offset += len;
        }
        return out;
    }
}

// Demo application class
class DBPARemoteTestApp {
private:
    std::string server_url_;
    std::unique_ptr<RemoteDataBatchProtectionAgent> agent_;
    std::unique_ptr<RemoteDataBatchProtectionAgent> float_agent_simple;
    std::unique_ptr<RemoteDataBatchProtectionAgent> float_agent_pooled;
    std::unique_ptr<RemoteDataBatchProtectionAgent> fixed_len_agent_;
    
public:
    DBPARemoteTestApp(const std::string& server_url) 
        : server_url_(server_url) {
        std::cout << "DBPA Network Demo Application" << std::endl;
        std::cout << "==============================" << std::endl;
        std::cout << "Server URL: " << server_url_ << std::endl;
        std::cout << std::endl;
    }
    
    // Initialize all DBPA agents
    bool Initialize() {
        std::cout << "Initializing DBPA agents..." << std::endl;
        
        HttpClientBase::ClientCredentials credentials = {
            {"client_id", "test_client_BBBB"},
            {"api_key", "test_key_BBBB"}
        };
        
        std::string app_context = "{\"user_id\": \"demo_user_123\"}";
        
        bool main_agent_ok = false;
        bool float_agent_ok = false;
        bool fixed_len_agent_ok = false;
        
        // Initialize the main agent for string/byte array data
        try {
            // Create HTTP client with server URL
            auto http_client = std::make_shared<HttplibClient>(server_url_, credentials);
            
            // Create the remote agent
            agent_ = std::make_unique<RemoteDataBatchProtectionAgent>(http_client);
            
            // Initialize the agent
            agent_->init(
                "demo_column",                 // column_name
                {},                            // configuration_map, not needed since the HTTP client is provided
                app_context,                   // app_context
                "demo_key_001",                // column_key_id
                Type::BYTE_ARRAY,              // datatype
                std::nullopt,                  // datatype_length (not needed for BYTE_ARRAY)
                CompressionCodec::SNAPPY,      // compression_type
                std::nullopt                   // column_encryption_metadata
            );
            
            std::cout << "OK: Main DBPA agent initialized successfully" << std::endl;
            main_agent_ok = true;
            
        } catch (const std::exception& e) {
            std::cerr << "ERROR: Failed to initialize main agent: " << e.what() << std::endl;
        }
        
        // Initialize the float agent for numeric data (Simpler http client)
        try {
            // Create HTTP client with server URL
            auto http_client = std::make_shared<HttplibClient>(server_url_, credentials);
            
            // Create the remote agent
            float_agent_simple = std::make_unique<RemoteDataBatchProtectionAgent>(http_client);
            
            // Initialize the agent
            float_agent_simple->init(
                "demo_float_column",           // column_name
                {},                            // configuration_map, not needed since the HTTP client is provided
                app_context,                   // app_context
                "demo_float_key_001",          // column_key_id
                Type::FLOAT,                   // datatype
                std::nullopt,                  // datatype_length (not needed for FLOAT)
                CompressionCodec::SNAPPY,      // compression_type
                std::nullopt                   // column_encryption_metadata
            );
            
            std::cout << "OK: Float DBPA agent initialized successfully" << std::endl;
            float_agent_ok = true;
            
        } catch (const std::exception& e) {
            std::cerr << "ERROR: Failed to initialize float agent: " << e.what() << std::endl;
        }
        
        // Initialize the float agent for numeric data (Using pooled HTTP client built inside RemoteDataBatchProtectionAgent)
        try {
            // Create the remote agent -- No injection of HTTP client, it will be built inside the agent on init()
            float_agent_pooled = std::make_unique<RemoteDataBatchProtectionAgent>();

            // Create connection config JSON
            nlohmann::json config_json;
            config_json["server_url"] = server_url_;
            config_json["credentials.client_id"] = "test_client_CCCC";
            config_json["credentials.api_key"] = "test_key_CCCC";
            std::string config_file_contents = config_json.dump(4);  // Pretty print with 4-space indent
            
            // Create a temporary connection config file
            std::string config_file_name = "test_connection_config.json";
            std::string config_file_path = std::filesystem::temp_directory_path() / config_file_name;
            std::ofstream config_file(config_file_path);
            config_file << config_file_contents;
            config_file.close();

            // Create the configuration map
            std::map<std::string, std::string> configuration_map = {
                {RemoteDataBatchProtectionAgent::k_connection_config_key_, config_file_path}};
            
            // Initialize the agent
            float_agent_pooled->init(
                "demo_float_column",           // column_name
                configuration_map,             // configuration_map, needed so the pooled HTTP client can be instantiated internally by the agent.
                app_context,                   // app_context
                "demo_float_key_001",          // column_key_id
                Type::FLOAT,                   // datatype
                std::nullopt,                  // datatype_length (not needed for FLOAT)
                CompressionCodec::SNAPPY,      // compression_type
                std::nullopt                   // column_encryption_metadata
            );
            
            std::cout << "OK: Float DBPA agent initialized successfully" << std::endl;
            float_agent_ok = true;
            
        } catch (const std::exception& e) {
            std::cerr << "ERROR: Failed to initialize float agent: " << e.what() << std::endl;
        }


        // Initialize the fixed-length agent for FIXED_LEN_BYTE_ARRAY data
        try {
            // Create HTTP client with server URL
            auto http_client = std::make_shared<HttplibClient>(server_url_, credentials);
            
            // Create the remote agent
            fixed_len_agent_ = std::make_unique<RemoteDataBatchProtectionAgent>(http_client);
            
            // Initialize the agent
            fixed_len_agent_->init(
                "demo_fixed_len_column",       // column_name
                {},                            // configuration_map, not needed since the HTTP client is provided
                app_context,                   // app_context
                "demo_fixed_len_key_001",      // column_key_id
                Type::FIXED_LEN_BYTE_ARRAY,    // datatype
                8,                             // datatype_length (8 bytes per element)
                CompressionCodec::SNAPPY,      // compression_type (input will be Snappy-compressed)
                std::nullopt                   // column_encryption_metadata
            );
            
            std::cout << "OK: Fixed-length DBPA agent initialized successfully" << std::endl;
            fixed_len_agent_ok = true;
            
        } catch (const std::exception& e) {
            std::cerr << "ERROR: Failed to initialize fixed-length agent: " << e.what() << std::endl;
        }
        
        bool all_ok = main_agent_ok && float_agent_ok && fixed_len_agent_ok;
        if (all_ok) {
            std::cout << "OK: All agents initialized successfully" << std::endl;
        } else {
            std::cerr << "ERROR: Some agents failed to initialize" << std::endl;
        }
        
        return all_ok;
    }
    
    // Demo encryption and decryption
    bool DemoEncryptionAndDecryption() {
        std::cout << "\n=== Encryption and Decryption Demo ===" << std::endl;
        
        std::vector<std::string> sample_data = {
            "Hello, DBPA Network Demo!",
            "This is sample data for encryption",
            "Special chars: !@#$%^&*()",
            "Numbers: 1234567890",
            "Long text: " + std::string(50 * 1000, 'B'),
            u8"UTF-8 sample: café 🚀 树 🌍",
            "Sample data for decryption demo",
            "Another piece of data to decrypt",
            "Final sample data"
        };
        
        bool all_succeeded = true;
        
        try {
            auto plaintext = MakeByteArrayListPayload(sample_data);
            auto compressed_plaintext = Compress(plaintext, CompressionCodec::SNAPPY);
            
            // Encrypt once for the combined payload
            std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
            auto encrypt_result = agent_->Encrypt(span<const uint8_t>(compressed_plaintext), encoding_attributes);
            
            if (!encrypt_result || !encrypt_result->success()) {
                std::cout << "  ERROR: Cannot demo decryption - encryption failed" << std::endl;
                if (encrypt_result) {
                    std::cout << "    Error: " << encrypt_result->error_message() << std::endl;
                }
                return false;
            }

            // Verify encryption metadata
            auto encryption_metadata = encrypt_result->encryption_metadata();
            if (!encryption_metadata || encryption_metadata->find("dbps_agent_version") == encryption_metadata->end()) {
                std::cout << "  ERROR: Encryption metadata verification failed" << std::endl;
                return false;
            }
            // Expect per-value encryption mode (DICTIONARY_PAGE uses encrypt_mode_dict_page)
            auto enc_mode_it = encryption_metadata->find("encrypt_mode_dict_page");
            if (enc_mode_it == encryption_metadata->end()) {
                std::cout << "  ERROR: Encryption metadata missing encrypt_mode_dict_page" << std::endl;
                return false;
            }
            if (enc_mode_it->second != "per_value") {
                std::cout << "  ERROR: Unexpected encryption_mode: " << enc_mode_it->second << std::endl;
                return false;
            }
            if (encryption_metadata->at("dbps_agent_version") != SEQUENCER_ENCRYPTION_METADATA_VERSION) {
                std::cout << "  ERROR: Encryption metadata version mismatch" << std::endl;
                std::cout << "    Expected: " << SEQUENCER_ENCRYPTION_METADATA_VERSION << std::endl;
                std::cout << "    Got: " << encryption_metadata->at("dbps_agent_version") << std::endl;
                return false;
            }
            std::cout << "  OK: Encryption metadata verified" << std::endl;
            std::cout << "    dbps_agent_version: " << encryption_metadata->at("dbps_agent_version") << std::endl;
            
            std::cout << "  OK: Encrypted (" << encrypt_result->size() << " bytes)" << std::endl;
            std::cout << "  OK: Ciphertext size: " << encrypt_result->size() << " bytes" << std::endl;

            // Show some details about the encrypted data
            auto ciphertext = encrypt_result->ciphertext();
            std::cout << "  OK: Ciphertext (first 32 bytes): ";
            for (size_t j = 0; j < std::min(size_t(32), ciphertext.size()); ++j) {
                printf("%02x", ciphertext[j]);
            }
            if (ciphertext.size() > 32) {
                std::cout << "...";
            }
            std::cout << std::endl;
            
            // Then decrypt
            agent_->UpdateEncryptionMetadata(encryption_metadata);
            auto decrypt_result = agent_->Decrypt(span<const uint8_t>(encrypt_result->ciphertext()), encoding_attributes);
            
            if (!decrypt_result || !decrypt_result->success()) {
                std::cout << "  ERROR: Decryption failed" << std::endl;
                if (decrypt_result) {
                    std::cout << "    Error: " << decrypt_result->error_message() << std::endl;
                }
                return false;
            }
            
            // Convert decrypted data back to string list
            auto decrypted_compressed = decrypt_result->plaintext();
            auto decrypted_plain = Decompress(
                std::vector<uint8_t>(decrypted_compressed.begin(), decrypted_compressed.end()),
                CompressionCodec::SNAPPY);
            auto decrypted_list = ParseByteArrayListPayload(decrypted_plain);
                            
            // Verify data integrity
            if (decrypted_list == sample_data) {
                std::cout << "  OK: Data integrity verified for combined payload (" << decrypted_list.size() << " items)" << std::endl;
            } else {
                std::cout << "  ERROR: Data integrity check failed for combined payload" << std::endl;
                all_succeeded = false;
            }
            
        } catch (const std::exception& e) {
            std::cout << "  ERROR: Exception: " << e.what() << std::endl;
            all_succeeded = false;
        }
        
        return all_succeeded;
    }
    
    // Demo round-trip operations
    bool DemoRoundTrip() {
        std::cout << "\n=== Round-Trip Demo ===" << std::endl;
        
        std::vector<std::string> test_cases = {
            "Simple text",
            "Text with symbols: !@#$%^&*()",
            "Numbers: 1234567890",
            "Mixed: Hello123!@#",
            "Empty string"
        };
        
        int success_count = 0;
        int total_count = test_cases.size();
        
        for (const auto& test_data : test_cases) {
            std::cout << "\nRound-trip test:" << std::endl;
            
            if (test_data.empty()) {
                std::cout << "  Testing: <empty string>" << std::endl;
            } else {
                std::cout << "  Testing: " << (test_data.length() > 30 ? test_data.substr(0, 30) + "..." : test_data) << std::endl;
            }
            
            try {
                auto plaintext = MakeByteArrayPayload(test_data);
                auto compressed_plaintext = Compress(plaintext, CompressionCodec::SNAPPY);
                
                // Encrypt
                std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
                auto encrypt_result = agent_->Encrypt(span<const uint8_t>(compressed_plaintext), encoding_attributes);
                
                if (!encrypt_result || !encrypt_result->success()) {
                    std::cout << "  ERROR: Encryption failed" << std::endl;
                    continue;
                }
                
                auto enc_meta = encrypt_result->encryption_metadata();
                auto enc_mode_it = enc_meta->find("encrypt_mode_dict_page");
                if (enc_mode_it == enc_meta->end()) {
                    std::cout << "  ERROR: Encryption metadata missing encrypt_mode_dict_page" << std::endl;
                    continue;
                }
                if (enc_mode_it->second != "per_value") {
                    std::cout << "  ERROR: Unexpected encryption_mode: " << enc_mode_it->second << std::endl;
                    continue;
                }

                // Decrypt
                agent_->UpdateEncryptionMetadata(encrypt_result->encryption_metadata());
                auto decrypt_result = agent_->Decrypt(span<const uint8_t>(encrypt_result->ciphertext()), encoding_attributes);
                
                if (!decrypt_result || !decrypt_result->success()) {
                    std::cout << "  ERROR: Decryption failed" << std::endl;
                    continue;
                }
                
                // Verify
                auto decrypted_compressed = decrypt_result->plaintext();
                auto decrypted_plain = Decompress(
                    std::vector<uint8_t>(decrypted_compressed.begin(), decrypted_compressed.end()),
                    CompressionCodec::SNAPPY);
                std::string decrypted_string = ParseByteArrayPayload(decrypted_plain);
                
                if (decrypted_string == test_data) {
                    std::cout << "  OK: Round-trip successful" << std::endl;
                    success_count++;
                } else {
                    std::cout << "  ERROR: Data mismatch" << std::endl;
                }
                
            } catch (const std::exception& e) {
                std::cout << "  ERROR: Exception: " << e.what() << std::endl;
            }
        }
        
        std::cout << "\nRound-trip summary: " << success_count << "/" << total_count << " successful" << std::endl;
        
        return success_count == total_count; // Return true only if all tests passed
    }
    
    // Demo float data encryption/decryption
    bool DemoFloatDataWithAgent(RemoteDataBatchProtectionAgent* agent, const std::string& agent_name) {
        std::cout << "\n--- Testing DemoFloatData with " << agent_name << " ---" << std::endl;
        
        if (!agent) {
            std::cout << "ERROR: " << agent_name << " not initialized" << std::endl;
            return false;
        }
        
        // Test with different float values
        std::vector<float> float_test_data = {
            1.5f, -2.25f, 3.14159f, 0.0f, -999.123456f,
            1234567.89f, -0.00001f, 42.0f
        };
        
        try {
            
            // Convert float data to binary format (little-endian)
            std::vector<uint8_t> float_binary_data;
            for (float f : float_test_data) {
                uint8_t* bytes = reinterpret_cast<uint8_t*>(&f);
                for (size_t i = 0; i < sizeof(float); ++i) {
                    float_binary_data.push_back(bytes[i]);
                }
            }
            
            std::cout << "Float test data (" << float_test_data.size() << " values): ";
            for (size_t i = 0; i < float_test_data.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << float_test_data[i];
            }
            std::cout << std::endl;
            std::cout << "Binary size: " << float_binary_data.size() << " bytes" << std::endl;
            
            // Build DATA_PAGE_V2 payload: level bytes (uncompressed) + compressed value bytes
            const int32_t def_len = 2;
            const int32_t rep_len = 1;
            std::vector<uint8_t> level_bytes(static_cast<size_t>(def_len + rep_len), 0x00);
            auto compressed_values = Compress(float_binary_data, CompressionCodec::SNAPPY);
            auto joined_plaintext = Join(level_bytes, compressed_values);

            std::map<std::string, std::string> float_encoding_attributes = {
                {"page_type", "DATA_PAGE_V2"},
                {"data_page_num_values", std::to_string(float_test_data.size())},
                {"data_page_max_definition_level", "1"},
                {"data_page_max_repetition_level", "0"},
                {"page_v2_definition_levels_byte_length", std::to_string(def_len)},
                {"page_v2_repetition_levels_byte_length", std::to_string(rep_len)},
                {"page_v2_num_nulls", "0"},
                {"page_v2_is_compressed", "true"},
                {"page_encoding", "PLAIN"}
            };

            auto encrypt_result = agent->Encrypt(span<const uint8_t>(joined_plaintext), float_encoding_attributes);
            
            if (!encrypt_result || !encrypt_result->success()) {
                std::cout << "ERROR: Float encryption failed" << std::endl;
                if (encrypt_result) {
                    std::cout << "  Error: " << encrypt_result->error_message() << std::endl;
                }
                return false;
            }
            
            std::cout << "OK: Float data encrypted successfully (" << encrypt_result->size() << " bytes)" << std::endl;
            auto float_enc_meta = encrypt_result->encryption_metadata();
            if (!float_enc_meta) {
                std::cout << "ERROR: Float encryption metadata missing" << std::endl;
                return false;
            }
            auto enc_mode_it = float_enc_meta->find("encrypt_mode_data_page");
            if (enc_mode_it == float_enc_meta->end()) {
                std::cout << "ERROR: Float encryption metadata missing encrypt_mode_data_page" << std::endl;
                return false;
            }
            if (enc_mode_it->second != "per_value") {
                std::cout << "ERROR: Unexpected float encryption_mode: " << enc_mode_it->second << std::endl;
                return false;
            }
            
            // Decrypt the float data
            agent->UpdateEncryptionMetadata(encrypt_result->encryption_metadata());
            auto decrypt_result = agent->Decrypt(span<const uint8_t>(encrypt_result->ciphertext()), float_encoding_attributes);
            
            if (!decrypt_result || !decrypt_result->success()) {
                std::cout << "ERROR: Float decryption failed" << std::endl;
                if (decrypt_result) {
                    std::cout << "  Error: " << decrypt_result->error_message() << std::endl;
                }
                return false;
            }
            
            std::cout << "OK: Float data decrypted successfully" << std::endl;
            
            // Compare payload as sent vs received
            auto decrypted_plaintext = decrypt_result->plaintext();
            if (decrypted_plaintext.size() != joined_plaintext.size() ||
                !std::equal(decrypted_plaintext.begin(), decrypted_plaintext.end(), joined_plaintext.begin())) {
                std::cout << "ERROR: Decrypted payload mismatch (joined plaintext bytes differ)" << std::endl;
                return false;
            }
            
            // Split level and value bytes, then decompress value bytes
            if (decrypted_plaintext.size() < static_cast<size_t>(def_len + rep_len)) {
                std::cout << "ERROR: Decrypted data too small for level bytes" << std::endl;
                return false;
            }
            std::vector<uint8_t> dec_level_bytes(decrypted_plaintext.begin(),
                                                 decrypted_plaintext.begin() + def_len + rep_len);
            if (dec_level_bytes.size() != level_bytes.size()) {
                std::cout << "ERROR: Decrypted level bytes size mismatch" << std::endl;
                return false;
            }
            std::vector<uint8_t> dec_compressed_values(decrypted_plaintext.begin() + def_len + rep_len,
                                                       decrypted_plaintext.end());
            auto decrypted_data = Decompress(dec_compressed_values, CompressionCodec::SNAPPY);
            if (decrypted_data.size() != float_binary_data.size()) {
                std::cout << "ERROR: Decrypted data size mismatch. Expected: " << float_binary_data.size() 
                         << ", Got: " << decrypted_data.size() << std::endl;
                return false;
            }
            
            std::vector<float> decrypted_floats;
            for (size_t i = 0; i < decrypted_data.size(); i += sizeof(float)) {
                float f;
                std::memcpy(&f, &decrypted_data[i], sizeof(float));
                decrypted_floats.push_back(f);
            }
            
            std::cout << "Decrypted float values: ";
            for (size_t i = 0; i < decrypted_floats.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << decrypted_floats[i];
            }
            std::cout << std::endl;
            
            // Verify data integrity - Expect exact match: Encryption/Decryption should not be lossy.
            bool integrity_ok = true;
            for (size_t i = 0; i < float_test_data.size(); ++i) {
                if (float_test_data[i] != decrypted_floats[i]) {
                    std::cout << "ERROR: Float value mismatch at index " << i 
                             << ". Expected: " << float_test_data[i] 
                             << ", Got: " << decrypted_floats[i] << std::endl;
                    integrity_ok = false;
                }
            }
            
            if (integrity_ok) {
                std::cout << "OK: Float data integrity verified with " << agent_name << std::endl;
                return true;
            } else {
                std::cout << "ERROR: Float data integrity check failed with " << agent_name << std::endl;
                return false;
            }
            
        } catch (const std::exception& e) {
            std::cout << "ERROR: Float demo exception with " << agent_name << ": " << e.what() << std::endl;
            return false;
        }
    }
    
    bool DemoFloatData() {
        std::cout << "\n=== Float Data Demo ===" << std::endl;
        
        bool simple_ok = DemoFloatDataWithAgent(float_agent_simple.get(), "Simple HTTP Client");
        bool pooled_ok = DemoFloatDataWithAgent(float_agent_pooled.get(), "Pooled HTTP Client");
        
        if (simple_ok && pooled_ok) {
            std::cout << "\nOK: Float data demo passed with both agents" << std::endl;
            return true;
        } else {
            std::cout << "\nERROR: Float data demo failed" << std::endl;
            std::cout << "  Simple client: " << (simple_ok ? "PASS" : "FAIL") << std::endl;
            std::cout << "  Pooled client: " << (pooled_ok ? "PASS" : "FAIL") << std::endl;
            return false;
        }
    }

    // Demo datatype_length functionality
    bool DemoDatatypeLength() {
        std::cout << "\n=== Datatype Length Demo ===" << std::endl;
        
        // Check if fixed-length agent is initialized
        if (!fixed_len_agent_) {
            std::cout << "ERROR: Fixed-length agent not initialized" << std::endl;
            return false;
        }
        
        try {
            // Test FIXED_LEN_BYTE_ARRAY with datatype_length
            std::cout << "Testing FIXED_LEN_BYTE_ARRAY with datatype_length..." << std::endl;
            
            // Create test data: 3 fixed-length strings of 8 bytes each
            std::string test_strings[] = {"Hello123", "World456", "Test7890"};
            std::vector<uint8_t> fixed_length_data;
            
            for (const auto& str : test_strings) {
                fixed_length_data.insert(fixed_length_data.end(), str.begin(), str.end());
            }
            
            std::cout << "Test data: 3 fixed-length strings (8 bytes each)" << std::endl;
            std::cout << "Original size: " << fixed_length_data.size() << " bytes" << std::endl;
            
            // Build DATA_PAGE_V1 payload: level bytes use RLE blocks with length prefixes
            std::vector<uint8_t> level_bytes;
            append_u32_le(level_bytes, 1); // repetition level block length
            level_bytes.push_back(0xAA);
            append_u32_le(level_bytes, 2); // definition level block length
            level_bytes.push_back(0xBB);
            level_bytes.push_back(0xCC);
            auto combined_uncompressed = Join(level_bytes, fixed_length_data);
            auto joined_plaintext = Compress(combined_uncompressed, CompressionCodec::SNAPPY);
            std::cout << "Compressed size: " << joined_plaintext.size() << " bytes" << std::endl;
            std::map<std::string, std::string> fixed_len_encoding_attributes = {
                {"page_type", "DATA_PAGE_V1"},
                {"data_page_num_values", "3"},
                {"data_page_max_repetition_level", "1"},
                {"data_page_max_definition_level", "1"},
                {"page_v1_repetition_level_encoding", "RLE"},
                {"page_v1_definition_level_encoding", "RLE"},
                {"page_encoding", "PLAIN"}
            };
            auto encrypt_result = fixed_len_agent_->Encrypt(span<const uint8_t>(joined_plaintext), fixed_len_encoding_attributes);
            
            if (!encrypt_result || !encrypt_result->success()) {
                std::cout << "ERROR: FIXED_LEN_BYTE_ARRAY encryption failed" << std::endl;
                if (encrypt_result) {
                    std::cout << "  Error: " << encrypt_result->error_message() << std::endl;
                }
                return false;
            }
            
            std::cout << "OK: FIXED_LEN_BYTE_ARRAY encrypted successfully (" << encrypt_result->size() << " bytes)" << std::endl;
            auto fixed_enc_meta = encrypt_result->encryption_metadata();
            if (!fixed_enc_meta) {
                std::cout << "ERROR: Fixed-length encryption metadata missing" << std::endl;
                return false;
            }
            auto enc_mode_it = fixed_enc_meta->find("encrypt_mode_data_page");
            if (enc_mode_it == fixed_enc_meta->end()) {
                std::cout << "ERROR: Fixed-length encryption metadata missing encrypt_mode_data_page" << std::endl;
                return false;
            }
            if (enc_mode_it->second != "per_value") {
                std::cout << "ERROR: Unexpected fixed-length encryption_mode: " << enc_mode_it->second << std::endl;
                return false;
            }
            
            // Test decryption
            fixed_len_agent_->UpdateEncryptionMetadata(encrypt_result->encryption_metadata());
            auto decrypt_result = fixed_len_agent_->Decrypt(span<const uint8_t>(encrypt_result->ciphertext()), fixed_len_encoding_attributes);
            
            if (!decrypt_result || !decrypt_result->success()) {
                std::cout << "ERROR: FIXED_LEN_BYTE_ARRAY decryption failed" << std::endl;
                if (decrypt_result) {
                    std::cout << "  Error: " << decrypt_result->error_message() << std::endl;
                }
                return false;
            }
            
            std::cout << "OK: FIXED_LEN_BYTE_ARRAY decrypted successfully" << std::endl;
            
            // Compare payload as sent vs received
            auto decrypted_plaintext = decrypt_result->plaintext();
            if (decrypted_plaintext.size() != joined_plaintext.size() ||
                !std::equal(decrypted_plaintext.begin(), decrypted_plaintext.end(), joined_plaintext.begin())) {
                std::cout << "ERROR: Decrypted payload mismatch (joined plaintext bytes differ)" << std::endl;
                return false;
            }
            
            // Decompress combined payload, split level/value
            auto decompressed_combined = Decompress(
                std::vector<uint8_t>(decrypted_plaintext.begin(), decrypted_plaintext.end()),
                CompressionCodec::SNAPPY);
            size_t offset = 0;
            if (offset + 4 > decompressed_combined.size()) {
                std::cout << "ERROR: Decompressed payload too small for rep level length" << std::endl;
                return false;
            }
            uint32_t rep_len = read_u32_le(decompressed_combined, static_cast<int>(offset));
            offset += 4;
            if (offset + rep_len > decompressed_combined.size()) {
                std::cout << "ERROR: Decompressed payload too small for rep level bytes" << std::endl;
                return false;
            }
            auto rep_bytes = std::vector<uint8_t>(decompressed_combined.begin() + static_cast<std::ptrdiff_t>(offset),
                                                  decompressed_combined.begin() + static_cast<std::ptrdiff_t>(offset + rep_len));
            offset += rep_len;

            if (offset + 4 > decompressed_combined.size()) {
                std::cout << "ERROR: Decompressed payload too small for def level length" << std::endl;
                return false;
            }
            uint32_t def_len = read_u32_le(decompressed_combined, static_cast<int>(offset));
            offset += 4;
            if (offset + def_len > decompressed_combined.size()) {
                std::cout << "ERROR: Decompressed payload too small for def level bytes" << std::endl;
                return false;
            }
            auto def_bytes = std::vector<uint8_t>(decompressed_combined.begin() + static_cast<std::ptrdiff_t>(offset),
                                                  decompressed_combined.begin() + static_cast<std::ptrdiff_t>(offset + def_len));
            offset += def_len;

            if (rep_bytes != std::vector<uint8_t>{0xAA} || def_bytes != std::vector<uint8_t>{0xBB, 0xCC}) {
                std::cout << "ERROR: Level bytes content mismatch" << std::endl;
                return false;
            }

            if (offset > decompressed_combined.size()) {
                std::cout << "ERROR: Offset beyond decompressed payload" << std::endl;
                return false;
            }
            auto value_bytes = std::vector<uint8_t>(decompressed_combined.begin() + static_cast<std::ptrdiff_t>(offset),
                                                    decompressed_combined.end());
            std::cout << "Decompressed value size: " << value_bytes.size() << " bytes" << std::endl;
            
            // Verify data integrity
            if (value_bytes.size() == fixed_length_data.size() && 
                std::equal(value_bytes.begin(), value_bytes.end(), fixed_length_data.begin(), fixed_length_data.end())) {
                std::cout << "OK: FIXED_LEN_BYTE_ARRAY data integrity verified" << std::endl;
            } else {
                std::cout << "ERROR: FIXED_LEN_BYTE_ARRAY data integrity check failed" << std::endl;
                std::cout << "  Expected size: " << fixed_length_data.size() << " bytes" << std::endl;
                std::cout << "  Got size: " << value_bytes.size() << " bytes" << std::endl;
                return false;
            }
            
            std::cout << "OK: Datatype length demo completed successfully" << std::endl;
            return true;
            
        } catch (const std::exception& e) {
            std::cout << "ERROR: Datatype length demo exception: " << e.what() << std::endl;
            return false;
        }
    }

    // Demo error handling
    bool DemoErrorHandling() {
        std::cout << "\n=== Error Handling Demo ===" << std::endl;
        
        // Test with empty data
        std::cout << "\nTesting empty data handling:" << std::endl;
        try {
            auto empty_data = MakeByteArrayPayload("");
            auto compressed_empty = Compress(empty_data, CompressionCodec::SNAPPY);
            std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
            auto result = agent_->Encrypt(span<const uint8_t>(compressed_empty), encoding_attributes);
            
            if (result && result->success()) {
                std::cout << "  OK: Empty data handled successfully" << std::endl;
            } else if (result && !result->success()) {
                std::cout << "  OK: Empty data properly rejected: " << result->error_message() << std::endl;
            } else {
                std::cout << "  WARNING: Unexpected null result for empty data" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "  OK: Exception caught for empty data: " << e.what() << std::endl;
        }
        
        // Test with very large data
        std::cout << "\nTesting large data handling:" << std::endl;
        try {
            std::string large_data(1000, 'X');  // 1KB of data
            auto plaintext = MakeByteArrayPayload(large_data);
            auto compressed_plaintext = Compress(plaintext, CompressionCodec::SNAPPY);
            std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
            auto result = agent_->Encrypt(span<const uint8_t>(compressed_plaintext), encoding_attributes);
            
            if (result && result->success()) {
                std::cout << "  OK: Large data (" << plaintext.size() << " bytes) encrypted successfully" << std::endl;
            } else if (result && !result->success()) {
                std::cout << "  OK: Large data properly rejected: " << result->error_message() << std::endl;
            } else {
                std::cout << "  WARNING: Unexpected null result for large data" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "  OK: Exception caught for large data: " << e.what() << std::endl;
        }
        
        return true; // Error handling demo always succeeds (it's testing error conditions)
    }
    
    // Run the complete demo
    void RunDemo() {
        std::cout << "Starting DBPA Network Demo..." << std::endl;
        std::cout << "Make sure the DBPS server is running at: " << server_url_ << std::endl;
        std::cout << std::endl;
        
        // Initialize
        if (!Initialize()) {
            std::cerr << "Demo cannot continue without proper initialization." << std::endl;
            return;
        }
        
        // Run demos and collect results
        bool encryption_ok = DemoEncryptionAndDecryption();
        bool roundtrip_ok = DemoRoundTrip();
        bool float_demo_ok = DemoFloatData();
        bool datatype_length_ok = DemoDatatypeLength();
        bool error_handling_ok = DemoErrorHandling();
        
        // Print summary
        std::cout << "\n=== Demo Summary ===" << std::endl;
        std::cout << "Encryption and Decryption Demo: " << (encryption_ok ? "PASS" : "FAIL") << std::endl;
        std::cout << "Round-Trip Demo: " << (roundtrip_ok ? "PASS" : "FAIL") << std::endl;
        std::cout << "Float Data Demo: " << (float_demo_ok ? "PASS" : "FAIL") << std::endl;
        std::cout << "Datatype Length Demo: " << (datatype_length_ok ? "PASS" : "FAIL") << std::endl;
        std::cout << "Error Handling Demo: " << (error_handling_ok ? "PASS" : "FAIL") << std::endl;
    }
};

int main(int argc, char* argv[]) {
    cxxopts::Options options("dbpa_remote_testapp", "DBPA Remote Test Application");
    
    options.add_options()
        ("s,server_url", "URL of the DBPS server", cxxopts::value<std::string>()->default_value("http://localhost:18080"))
        ("h,help", "Display this help message");
    
    try {
        auto result = options.parse(argc, argv);
        
        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            return 0;
        }
        
        std::string server_url = result["server_url"].as<std::string>();
        
        // Create and run the demo
        DBPARemoteTestApp demo(server_url);
        demo.RunDemo();
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        std::cout << options.help() << std::endl;
        return 1;
    }
}
