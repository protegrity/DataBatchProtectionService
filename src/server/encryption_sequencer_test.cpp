#include "encryption_sequencer.h"
#include <iostream>
#include <cassert>
#include <string>

// Test helper function to print test results
void PrintTestResult(const std::string& test_name, bool passed) {
    std::cout << (passed ? "PASS" : "FAIL") << ": " << test_name << std::endl;
}

// Test helper function to check if encryption/decryption works correctly
bool TestEncryptionDecryption() {
    // Test 1: Basic encryption/decryption round trip
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY",      // datatype
            "UNCOMPRESSED",    // compression
            "RAW_C_DATA",      // format
            "BASE64",          // encoding
            "UNCOMPRESSED",    // encrypted_compression
            "test_key_123"     // key_id
        );
        
        // Test data: "Hello, World!" in base64
        std::string test_data = "SGVsbG8sIFdvcmxkIQ==";
        
        // Test encryption
        bool encrypt_result = sequencer.ConvertAndEncrypt(test_data);
        if (!encrypt_result) {
            std::cout << "Encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
    }
    
    // Test 2: Different key_id produces different encryption
    {
        DataBatchEncryptionSequencer sequencer1(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "key1"
        );
        
        DataBatchEncryptionSequencer sequencer2(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "key2"
        );
        
        std::string test_data = "SGVsbG8sIFdvcmxkIQ==";
        
        bool result1 = sequencer1.ConvertAndEncrypt(test_data);
        bool result2 = sequencer2.ConvertAndEncrypt(test_data);
        
        if (!result1 || !result2) {
            std::cout << "Different key encryption test failed" << std::endl;
            return false;
        }
    }
    
    // Test 3: Same key_id produces consistent encryption
    {
        DataBatchEncryptionSequencer sequencer1(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "same_key"
        );
        
        DataBatchEncryptionSequencer sequencer2(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "same_key"
        );
        
        std::string test_data = "SGVsbG8sIFdvcmxkIQ==";
        
        bool result1 = sequencer1.ConvertAndEncrypt(test_data);
        bool result2 = sequencer2.ConvertAndEncrypt(test_data);
        
        if (!result1 || !result2) {
            std::cout << "Same key encryption test failed" << std::endl;
            return false;
        }
    }
    
    // Test 4: Empty data encryption
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        
        // This should fail because empty input is rejected
        bool result = sequencer.ConvertAndEncrypt("");
        if (result) {
            std::cout << "Empty data encryption should have failed" << std::endl;
            return false;
        }
    }
    
    // Test 5: Binary data encryption
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        
        // Binary data: 0x00, 0x01, 0x02, 0x03, 0x04, 0x05
        std::string binary_data = "AAECAwQF";
        
        bool result = sequencer.ConvertAndEncrypt(binary_data);
        if (!result) {
            std::cout << "Binary data encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
    }
    
    return true;
}

// Test parameter validation
bool TestParameterValidation() {
    // Test 1: Valid parameters
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("SGVsbG8sIFdvcmxkIQ==");
        if (!result) {
            std::cout << "Valid parameters test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
    }
    
    // Test 2: Invalid compression
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "GZIP", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("SGVsbG8sIFdvcmxkIQ==");
        if (result) {
            std::cout << "Invalid compression test should have failed" << std::endl;
            return false;
        }
        if (sequencer.error_stage_ != "parameter_validation") {
            std::cout << "Wrong error stage for invalid compression: " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    // Test 3: Invalid encoding
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "UTF8", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("SGVsbG8sIFdvcmxkIQ==");
        if (result) {
            std::cout << "Invalid encoding test should have failed" << std::endl;
            return false;
        }
        if (sequencer.error_stage_ != "parameter_validation") {
            std::cout << "Wrong error stage for invalid encoding: " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    // Test 4: Invalid format
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "JSON", "BASE64", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("SGVsbG8sIFdvcmxkIQ==");
        if (result) {
            std::cout << "Invalid format test should have failed" << std::endl;
            return false;
        }
        if (sequencer.error_stage_ != "parameter_validation") {
            std::cout << "Wrong error stage for invalid format: " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    return true;
}

// Test input validation
bool TestInputValidation() {
    // Test 1: Empty plaintext
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("");
        if (result) {
            std::cout << "Empty plaintext test should have failed" << std::endl;
            return false;
        }
        if (sequencer.error_stage_ != "validation") {
            std::cout << "Wrong error stage for empty plaintext: " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    // Test 2: Empty ciphertext
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndDecrypt("");
        if (result) {
            std::cout << "Empty ciphertext test should have failed" << std::endl;
            return false;
        }
        if (sequencer.error_stage_ != "validation") {
            std::cout << "Wrong error stage for empty ciphertext: " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    // Test 3: Empty key_id
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", ""
        );
        bool result = sequencer.ConvertAndEncrypt("SGVsbG8sIFdvcmxkIQ==");
        if (result) {
            std::cout << "Empty key_id test should have failed" << std::endl;
            return false;
        }
        if (sequencer.error_stage_ != "validation") {
            std::cout << "Wrong error stage for empty key_id: " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    return true;
}

// Test enum conversion
bool TestEnumConversion() {
    // Test 1: Valid enum conversion
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("SGVsbG8sIFdvcmxkIQ==");
        if (!result) {
            std::cout << "Valid enum conversion test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
    }
    
    // Test 2: Invalid datatype
    {
        DataBatchEncryptionSequencer sequencer(
            "INVALID_TYPE", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("SGVsbG8sIFdvcmxkIQ==");
        if (result) {
            std::cout << "Invalid datatype test should have failed" << std::endl;
            return false;
        }
        if (sequencer.error_stage_ != "datatype_conversion") {
            std::cout << "Wrong error stage for invalid datatype: " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    return true;
}

// Test base64 decoding
bool TestBase64Decoding() {
    // Test 1: Valid base64 - "Hello, World!"
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("SGVsbG8sIFdvcmxkIQ==");
        if (!result) {
            std::cout << "Valid base64 test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
    }
    
    // Test 2: Valid base64 - empty string
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("");
        if (result) {
            std::cout << "Empty base64 test should have failed (empty input)" << std::endl;
            return false;
        }
    }
    
    // Test 3: Valid base64 - single character
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("QQ=="); // "A"
        if (!result) {
            std::cout << "Single character base64 test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
    }
    
    // Test 4: Valid base64 - binary data
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("AAECAwQF"); // Binary data: 0x00, 0x01, 0x02, 0x03, 0x04, 0x05
        if (!result) {
            std::cout << "Binary data base64 test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
    }
    
    // Test 5: Invalid base64 - garbage characters
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("InvalidBase64!@#");
        if (result) {
            std::cout << "Invalid base64 test should have failed" << std::endl;
            return false;
        }
        if (sequencer.error_stage_ != "base64_decoding") {
            std::cout << "Wrong error stage for invalid base64: " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    // Test 6: Invalid base64 - incomplete padding
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "RAW_C_DATA", "BASE64", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("SGVsbG8sIFdvcmxkIQ"); // Missing padding
        if (result) {
            std::cout << "Incomplete padding base64 test should have failed" << std::endl;
            return false;
        }
        if (sequencer.error_stage_ != "base64_decoding") {
            std::cout << "Wrong error stage for incomplete padding: " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    return true;
}



int main() {
    std::cout << "Running DataBatchEncryptionSequencer tests..." << std::endl;
    std::cout << "=============================================" << std::endl;
    
    bool all_tests_passed = true;
    
    // Run all test suites
    all_tests_passed &= TestParameterValidation();
    PrintTestResult("Parameter Validation", all_tests_passed);
    
    all_tests_passed &= TestInputValidation();
    PrintTestResult("Input Validation", all_tests_passed);
    
    all_tests_passed &= TestEnumConversion();
    PrintTestResult("Enum Conversion", all_tests_passed);
    
    all_tests_passed &= TestBase64Decoding();
    PrintTestResult("Base64 Decoding", all_tests_passed);
    
    all_tests_passed &= TestEncryptionDecryption();
    PrintTestResult("Encryption/Decryption", all_tests_passed);
    
    std::cout << "=============================================" << std::endl;
    if (all_tests_passed) {
        std::cout << "All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "Some tests failed!" << std::endl;
        return 1;
    }
}
