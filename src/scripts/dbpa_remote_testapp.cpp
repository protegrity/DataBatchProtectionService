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
#include <cxxopts.hpp>

// Include the necessary headers from the project
#include "../common/dbpa_remote.h"
#include "../client/httplib_client.h"
#include "../common/enums.h"
#include "../server/compression_utils.h"
#include "tcb/span.hpp"

using namespace dbps::external;
using namespace dbps::enum_utils;
using namespace dbps::compression;

template <typename T>
using span = tcb::span<T>;

namespace {
    const std::map<std::string, std::string> VALID_ENCRYPTION_METADATA = {
        {"dbps_agent_version", "v0.01_unittest"}, {"encryption_mode", "per_block"}};
    const std::string SEQUENCER_ENCRYPTION_METADATA_VERSION = "v0.01";
}

// Demo application class
class DBPARemoteTestApp {
private:
    std::string server_url_;
    std::unique_ptr<RemoteDataBatchProtectionAgent> agent_;
    std::unique_ptr<RemoteDataBatchProtectionAgent> float_agent_;
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
        
        // Common configuration for all agents
        std::map<std::string, std::string> connection_config = {
            {"server_url", server_url_}
        };
        
        std::string app_context = "{\"user_id\": \"demo_user_123\"}";
        
        bool main_agent_ok = false;
        bool float_agent_ok = false;
        bool fixed_len_agent_ok = false;
        
        // Initialize the main agent for string/byte array data
        try {
            // Create HTTP client with server URL
            auto http_client = std::make_shared<HttplibClient>(server_url_);
            
            // Create the remote agent
            agent_ = std::make_unique<RemoteDataBatchProtectionAgent>(http_client);
            
            // Initialize the agent
            agent_->init(
                "demo_column",                 // column_name
                connection_config,             // connection_config
                app_context,                   // app_context
                "demo_key_001",                // column_key_id
                Type::UNDEFINED,               // datatype
                std::nullopt,                  // datatype_length (not needed for UNDEFINED)
                CompressionCodec::UNCOMPRESSED, // compression_type
                VALID_ENCRYPTION_METADATA       // column_encryption_metadata -- used only during /decrypt calls
            );
            
            std::cout << "OK: Main DBPA agent initialized successfully" << std::endl;
            main_agent_ok = true;
            
        } catch (const std::exception& e) {
            std::cerr << "ERROR: Failed to initialize main agent: " << e.what() << std::endl;
        }
        
        // Initialize the float agent for numeric data
        try {
            // Create HTTP client with server URL
            auto http_client = std::make_shared<HttplibClient>(server_url_);
            
            // Create the remote agent
            float_agent_ = std::make_unique<RemoteDataBatchProtectionAgent>(http_client);
            
            // Initialize the agent
            float_agent_->init(
                "demo_float_column",           // column_name
                connection_config,             // connection_config
                app_context,                   // app_context
                "demo_float_key_001",          // column_key_id
                Type::FLOAT,                   // datatype
                std::nullopt,                  // datatype_length (not needed for FLOAT)
                CompressionCodec::UNCOMPRESSED, // compression_type
                VALID_ENCRYPTION_METADATA       // column_encryption_metadata -- used only during /decrypt calls
            );
            
            std::cout << "OK: Float DBPA agent initialized successfully" << std::endl;
            float_agent_ok = true;
            
        } catch (const std::exception& e) {
            std::cerr << "ERROR: Failed to initialize float agent: " << e.what() << std::endl;
        }
        
        // Initialize the fixed-length agent for FIXED_LEN_BYTE_ARRAY data
        try {
            // Create HTTP client with server URL
            auto http_client = std::make_shared<HttplibClient>(server_url_);
            
            // Create the remote agent
            fixed_len_agent_ = std::make_unique<RemoteDataBatchProtectionAgent>(http_client);
            
            // Initialize the agent
            fixed_len_agent_->init(
                "demo_fixed_len_column",       // column_name
                connection_config,             // connection_config
                app_context,                   // app_context
                "demo_fixed_len_key_001",      // column_key_id
                Type::FIXED_LEN_BYTE_ARRAY,   // datatype
                8,                            // datatype_length (8 bytes per element)
                CompressionCodec::SNAPPY,      // compression_type (input will be Snappy-compressed)
                VALID_ENCRYPTION_METADATA       // column_encryption_metadata -- used only during /decrypt calls
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
            // "Long text: " + std::string(50 * 1000 * 1000, 'B'),
            "Sample data for decryption demo",
            "Another piece of data to decrypt",
            "Final sample data"
        };
        
        bool all_succeeded = true;
        
        for (const auto& original_data : sample_data) {
            std::cout << "\nEncrypting sample (" << original_data.length() << " bytes):" << std::endl;
            std::cout << "  Original: " << (original_data.length() > 50 ? original_data.substr(0, 50) + "..." : original_data) << std::endl;
            
            try {
                std::vector<uint8_t> plaintext(original_data.begin(), original_data.end());
                
                // First encrypt
                std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
                auto encrypt_result = agent_->Encrypt(span<const uint8_t>(plaintext), encoding_attributes);
                
                if (!encrypt_result || !encrypt_result->success()) {
                    std::cout << "  ERROR: Cannot demo decryption - encryption failed" << std::endl;
                    if (encrypt_result) {
                        std::cout << "    Error: " << encrypt_result->error_message() << std::endl;
                    }
                    all_succeeded = false;
                    continue;
                }

                // Verify encryption metadata
                auto encryption_metadata = encrypt_result->encryption_metadata();
                if (!encryption_metadata || encryption_metadata->find("dbps_agent_version") == encryption_metadata->end()) {
                    std::cout << "  ERROR: Encryption metadata verification failed" << std::endl;
                    all_succeeded = false;
                    continue;
                }
                if (encryption_metadata->at("dbps_agent_version") != SEQUENCER_ENCRYPTION_METADATA_VERSION) {
                    std::cout << "  ERROR: Encryption metadata version mismatch" << std::endl;
                    std::cout << "    Expected: " << SEQUENCER_ENCRYPTION_METADATA_VERSION << std::endl;
                    std::cout << "    Got: " << encryption_metadata->at("dbps_agent_version") << std::endl;
                    all_succeeded = false;
                    continue;
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
                auto decrypt_result = agent_->Decrypt(span<const uint8_t>(encrypt_result->ciphertext()), encoding_attributes);
                
                if (!decrypt_result || !decrypt_result->success()) {
                    std::cout << "  ERROR: Decryption failed" << std::endl;
                    if (decrypt_result) {
                        std::cout << "    Error: " << decrypt_result->error_message() << std::endl;
                    }
                    all_succeeded = false;
                    continue;
                }
                
                // Convert decrypted data back to string
                std::string decrypted_string(decrypt_result->plaintext().begin(), 
                                           decrypt_result->plaintext().end());
                                
                std::cout << "  OK: Decrypted: " << (decrypted_string.length() > 50 ? decrypted_string.substr(0, 50) + "..." : decrypted_string) << std::endl;
                
                // Verify data integrity
                if (decrypted_string == original_data) {
                    std::cout << "  OK: Data integrity verified" << std::endl;
                } else {
                    std::cout << "  ERROR: Data integrity check failed" << std::endl;
                    all_succeeded = false;
                }
                
            } catch (const std::exception& e) {
                std::cout << "  ERROR: Exception: " << e.what() << std::endl;
                all_succeeded = false;
            }
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
                std::vector<uint8_t> plaintext(test_data.begin(), test_data.end());
                
                // Encrypt
                std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
                auto encrypt_result = agent_->Encrypt(span<const uint8_t>(plaintext), encoding_attributes);
                
                if (!encrypt_result || !encrypt_result->success()) {
                    std::cout << "  ERROR: Encryption failed" << std::endl;
                    continue;
                }
                
                // Decrypt
                auto decrypt_result = agent_->Decrypt(span<const uint8_t>(encrypt_result->ciphertext()), encoding_attributes);
                
                if (!decrypt_result || !decrypt_result->success()) {
                    std::cout << "  ERROR: Decryption failed" << std::endl;
                    continue;
                }
                
                // Verify
                std::string decrypted_string(decrypt_result->plaintext().begin(), 
                                           decrypt_result->plaintext().end());
                
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
    bool DemoFloatData() {
        std::cout << "\n=== Float Data Demo ===" << std::endl;
        
        // Check if float agent is initialized
        if (!float_agent_) {
            std::cout << "ERROR: Float agent not initialized" << std::endl;
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
            
            // Encrypt the float data
            std::map<std::string, std::string> float_encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
            auto encrypt_result = float_agent_->Encrypt(span<const uint8_t>(float_binary_data), float_encoding_attributes);
            
            if (!encrypt_result || !encrypt_result->success()) {
                std::cout << "ERROR: Float encryption failed" << std::endl;
                if (encrypt_result) {
                    std::cout << "  Error: " << encrypt_result->error_message() << std::endl;
                }
                return false;
            }
            
            std::cout << "OK: Float data encrypted successfully (" << encrypt_result->size() << " bytes)" << std::endl;
            
            // Decrypt the float data
            auto decrypt_result = float_agent_->Decrypt(span<const uint8_t>(encrypt_result->ciphertext()), float_encoding_attributes);
            
            if (!decrypt_result || !decrypt_result->success()) {
                std::cout << "ERROR: Float decryption failed" << std::endl;
                if (decrypt_result) {
                    std::cout << "  Error: " << decrypt_result->error_message() << std::endl;
                }
                return false;
            }
            
            std::cout << "OK: Float data decrypted successfully" << std::endl;
            
            // Convert decrypted binary back to float values
            auto decrypted_data = decrypt_result->plaintext();
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
                std::cout << "OK: Float data integrity verified" << std::endl;
                return true;
            } else {
                std::cout << "ERROR: Float data integrity check failed" << std::endl;
                return false;
            }
            
        } catch (const std::exception& e) {
            std::cout << "ERROR: Float demo exception: " << e.what() << std::endl;
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
            
            // Compress the test data using Snappy before sending to server
            std::vector<uint8_t> fixed_length_data_compressed = Compress(fixed_length_data, CompressionCodec::SNAPPY);
            std::cout << "Compressed size: " << fixed_length_data_compressed.size() << " bytes" << std::endl;

            // Test encryption with FIXED_LEN_BYTE_ARRAY and datatype_length
            // The server will decompress the fixed_length_data_compressed, encrypt it, and compress the encrypted result
            std::map<std::string, std::string> fixed_len_encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
            auto encrypt_result = fixed_len_agent_->Encrypt(span<const uint8_t>(fixed_length_data_compressed), fixed_len_encoding_attributes);
            
            if (!encrypt_result || !encrypt_result->success()) {
                std::cout << "ERROR: FIXED_LEN_BYTE_ARRAY encryption failed" << std::endl;
                if (encrypt_result) {
                    std::cout << "  Error: " << encrypt_result->error_message() << std::endl;
                }
                return false;
            }
            
            std::cout << "OK: FIXED_LEN_BYTE_ARRAY encrypted successfully (" << encrypt_result->size() << " bytes)" << std::endl;
            
            // Test decryption
            auto decrypt_result = fixed_len_agent_->Decrypt(span<const uint8_t>(encrypt_result->ciphertext()), fixed_len_encoding_attributes);
            
            if (!decrypt_result || !decrypt_result->success()) {
                std::cout << "ERROR: FIXED_LEN_BYTE_ARRAY decryption failed" << std::endl;
                if (decrypt_result) {
                    std::cout << "  Error: " << decrypt_result->error_message() << std::endl;
                }
                return false;
            }
            
            std::cout << "OK: FIXED_LEN_BYTE_ARRAY decrypted successfully" << std::endl;
            
            // The server returns compressed plaintext (same compression as input)
            // Decompress it before comparing with original data
            auto decrypted_compressed_span = decrypt_result->plaintext();
            std::vector<uint8_t> decrypted_compressed(decrypted_compressed_span.begin(), decrypted_compressed_span.end());
            std::vector<uint8_t> decrypted_data = Decompress(decrypted_compressed, CompressionCodec::SNAPPY);
            std::cout << "Decrypted compressed size: " << decrypted_compressed.size() << " bytes" << std::endl;
            std::cout << "Decrypted uncompressed size: " << decrypted_data.size() << " bytes" << std::endl;
            
            // Verify data integrity
            if (decrypted_data.size() == fixed_length_data.size() && 
                std::equal(decrypted_data.begin(), decrypted_data.end(), fixed_length_data.begin(), fixed_length_data.end())) {
                std::cout << "OK: FIXED_LEN_BYTE_ARRAY data integrity verified" << std::endl;
            } else {
                std::cout << "ERROR: FIXED_LEN_BYTE_ARRAY data integrity check failed" << std::endl;
                std::cout << "  Expected size: " << fixed_length_data.size() << " bytes" << std::endl;
                std::cout << "  Got size: " << decrypted_data.size() << " bytes" << std::endl;
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
            std::vector<uint8_t> empty_data;
            std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
            auto result = agent_->Encrypt(span<const uint8_t>(empty_data), encoding_attributes);
            
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
            std::vector<uint8_t> plaintext(large_data.begin(), large_data.end());
            std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
            auto result = agent_->Encrypt(span<const uint8_t>(plaintext), encoding_attributes);
            
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
