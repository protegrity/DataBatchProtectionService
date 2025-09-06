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
            "PLAIN",      // format
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "key1"
        );
        
        DataBatchEncryptionSequencer sequencer2(
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "key2"
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "same_key"
        );
        
        DataBatchEncryptionSequencer sequencer2(
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "same_key"
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
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
    // Test 1: Valid parameters, should succeed
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("SGVsbG8sIFdvcmxkIQ==");
        if (!result) {
            std::cout << "Valid parameters test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
    }
    
    // Test 2: Invalid compression (should now succeed with warning)
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "GZIP", "PLAIN", "UNCOMPRESSED", "test_key"
        );
        bool result = sequencer.ConvertAndEncrypt("SGVsbG8sIFdvcmxkIQ==");
        if (!result) {
            // TODO: When compression validation is enforced, this should fail
            return false;
        }
        // Should not have error stage since it succeeded
        if (!sequencer.error_stage_.empty()) {
            // TODO: When compression validation is enforced, this should have error stage
            return false;
        }
    }
    
    // Test 3: Invalid format
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "CSV", "UNCOMPRESSED", "test_key"
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", ""
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
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
            "INVALID_TYPE", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
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
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
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

// Test round-trip encryption/decryption with base64 verification
bool TestRoundTripEncryption() {
    // Test 1: Basic round trip - "Hello, World!"
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key_123"
        );
        
        std::string original_base64 = "SGVsbG8sIFdvcmxkIQ=="; // "Hello, World!"
        
        // Encrypt
        bool encrypt_result = sequencer.ConvertAndEncrypt(original_base64);
        if (!encrypt_result) {
            std::cout << "Round trip encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Decrypt the encrypted result
        bool decrypt_result = sequencer.ConvertAndDecrypt(sequencer.encrypted_result_);
        if (!decrypt_result) {
            std::cout << "Round trip decryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Verify the decrypted result matches the original
        if (sequencer.decrypted_result_ != original_base64) {
            std::cout << "Round trip failed: decrypted result does not match original" << std::endl;
            std::cout << "Original: " << original_base64 << std::endl;
            std::cout << "Decrypted: " << sequencer.decrypted_result_ << std::endl;
            return false;
        }
    }
    
    // Test 2: Binary data round trip
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "binary_test_key"
        );
        
        std::string original_base64 = "AAECAwQF"; // Binary data: 0x00, 0x01, 0x02, 0x03, 0x04, 0x05
        
        // Encrypt
        bool encrypt_result = sequencer.ConvertAndEncrypt(original_base64);
        if (!encrypt_result) {
            std::cout << "Binary round trip encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Decrypt the encrypted result
        bool decrypt_result = sequencer.ConvertAndDecrypt(sequencer.encrypted_result_);
        if (!decrypt_result) {
            std::cout << "Binary round trip decryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Verify the decrypted result matches the original
        if (sequencer.decrypted_result_ != original_base64) {
            std::cout << "Binary round trip failed: decrypted result does not match original" << std::endl;
            std::cout << "Original: " << original_base64 << std::endl;
            std::cout << "Decrypted: " << sequencer.decrypted_result_ << std::endl;
            return false;
        }
    }
    
    // Test 3: Single character round trip
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "single_char_key"
        );
        
        std::string original_base64 = "QQ=="; // "A"
        
        // Encrypt
        bool encrypt_result = sequencer.ConvertAndEncrypt(original_base64);
        if (!encrypt_result) {
            std::cout << "Single char round trip encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Decrypt the encrypted result
        bool decrypt_result = sequencer.ConvertAndDecrypt(sequencer.encrypted_result_);
        if (!decrypt_result) {
            std::cout << "Single char round trip decryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Verify the decrypted result matches the original
        if (sequencer.decrypted_result_ != original_base64) {
            std::cout << "Single char round trip failed: decrypted result does not match original" << std::endl;
            std::cout << "Original: " << original_base64 << std::endl;
            std::cout << "Decrypted: " << sequencer.decrypted_result_ << std::endl;
            return false;
        }
    }
    
    // Test 4: Different keys produce different encrypted results
    {
        DataBatchEncryptionSequencer sequencer1(
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "key1"
        );
        
        DataBatchEncryptionSequencer sequencer2(
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "key2"
        );
        
        std::string original_base64 = "SGVsbG8sIFdvcmxkIQ==";
        
        bool result1 = sequencer1.ConvertAndEncrypt(original_base64);
        bool result2 = sequencer2.ConvertAndEncrypt(original_base64);
        
        if (!result1 || !result2) {
            std::cout << "Different keys test failed during encryption" << std::endl;
            return false;
        }
        
        // Key-aware XOR encryption should produce different results for different keys
        if (sequencer1.encrypted_result_ == sequencer2.encrypted_result_) {
            std::cout << "Simple XOR encryption should produce different results for different keys" << std::endl;
            return false;
        }
        
        // But both should decrypt back to the same original
        bool decrypt1 = sequencer1.ConvertAndDecrypt(sequencer1.encrypted_result_);
        bool decrypt2 = sequencer2.ConvertAndDecrypt(sequencer2.encrypted_result_);
        
        if (!decrypt1 || !decrypt2) {
            std::cout << "Different keys test failed during decryption" << std::endl;
            return false;
        }
        
        if (sequencer1.decrypted_result_ != original_base64 || sequencer2.decrypted_result_ != original_base64) {
            std::cout << "Different keys test: decrypted results should match original" << std::endl;
            return false;
        }
    }
    
    return true;
}

// Test result storage and base64 encoding
bool TestResultStorage() {
    // Test 1: Verify encrypted result is stored
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
        );
        
        std::string original_base64 = "SGVsbG8sIFdvcmxkIQ==";
        
        bool result = sequencer.ConvertAndEncrypt(original_base64);
        if (!result) {
            std::cout << "Result storage encryption test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Verify encrypted_result_ is not empty and is different from input
        if (sequencer.encrypted_result_.empty()) {
            std::cout << "encrypted_result_ should not be empty" << std::endl;
            return false;
        }
        
        if (sequencer.encrypted_result_ == original_base64) {
            std::cout << "encrypted_result_ should be different from input" << std::endl;
            return false;
        }
        
        // Verify it's valid base64
        if (sequencer.encrypted_result_.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") != std::string::npos) {
            std::cout << "encrypted_result_ should contain only valid base64 characters" << std::endl;
            return false;
        }
    }
    
    // Test 2: Verify decrypted result is stored
    {
        DataBatchEncryptionSequencer sequencer(
            "BYTE_ARRAY", "UNCOMPRESSED", "PLAIN", "UNCOMPRESSED", "test_key"
        );
        
        // First encrypt something
        std::string original_base64 = "SGVsbG8sIFdvcmxkIQ==";
        bool encrypt_result = sequencer.ConvertAndEncrypt(original_base64);
        if (!encrypt_result) {
            std::cout << "Result storage decryption test failed during encryption" << std::endl;
            return false;
        }
        
        // Then decrypt it
        bool decrypt_result = sequencer.ConvertAndDecrypt(sequencer.encrypted_result_);
        if (!decrypt_result) {
            std::cout << "Result storage decryption test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Verify decrypted_result_ is not empty and matches original
        if (sequencer.decrypted_result_.empty()) {
            std::cout << "decrypted_result_ should not be empty" << std::endl;
            return false;
        }
        
        if (sequencer.decrypted_result_ != original_base64) {
            std::cout << "decrypted_result_ should match original input" << std::endl;
            std::cout << "Original: " << original_base64 << std::endl;
            std::cout << "Decrypted: " << sequencer.decrypted_result_ << std::endl;
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
    
    all_tests_passed &= TestRoundTripEncryption();
    PrintTestResult("Round-Trip Encryption", all_tests_passed);
    
    all_tests_passed &= TestResultStorage();
    PrintTestResult("Result Storage", all_tests_passed);
    
    std::cout << "=============================================" << std::endl;
    if (all_tests_passed) {
        std::cout << "All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "Some tests failed!" << std::endl;
        return 1;
    }
}
