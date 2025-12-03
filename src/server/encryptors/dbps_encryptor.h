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

#include <cstdint>
#include <string>
#include <utility>
#include <vector>
#include "../exceptions.h"
#include "../decoding_utils.h"

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

/**
 * Interface for encryption/decryption operations in the Data Batch Protection Service.
 * 
 * This interface provides methods for both block-level and value-level encryption/decryption.
 * Block encryption operates on raw byte arrays, while value encryption works with typed data structures.
 * 
 * Context parameters (key_id, column_name, user_id, application_context) are provided
 * via the constructor and stored by implementations for use in encryption/decryption operations.
 */
class DBPS_EXPORT DBPSEncryptor {
public:
    /**
     * Constructor that initializes the encryptor with context parameters.
     * 
     * @param key_id The encryption key identifier
     * @param column_name The name of the column being encrypted/decrypted
     * @param user_id The user identifier for context
     * @param application_context Additional application context information
     */
    DBPSEncryptor(
        const std::string& key_id,
        const std::string& column_name,
        const std::string& user_id,
        const std::string& application_context)
        : key_id_(key_id),
          column_name_(column_name),
          user_id_(user_id),
          application_context_(application_context) {}

    virtual ~DBPSEncryptor() = default;

    /**
     * Encrypts a block of data using block-level encryption.
     * 
     * @param data The plaintext data to encrypt as a vector of bytes
     * @return The encrypted data as a vector of bytes
     * @throws InvalidInputException if the input data is invalid or empty
     * @throws DBPSUnsupportedException if the encryption operation is not supported
     */
    virtual std::vector<uint8_t> EncryptBlock(const std::vector<uint8_t>& data) = 0;

    /**
     * Decrypts a block of data using block-level decryption.
     * 
     * @param data The ciphertext data to decrypt as a vector of bytes
     * @return The decrypted data as a vector of bytes
     * @throws InvalidInputException if the input data is invalid, empty, or corrupted
     * @throws DBPSUnsupportedException if the decryption operation is not supported
     */
    virtual std::vector<uint8_t> DecryptBlock(const std::vector<uint8_t>& data) = 0;

    /**
     * Integration point: Encryption function based on list of values that will be implemented by Protegrity.
     * 
     * The context-rich encryptor can use the additional parameters stored in the constructor:
     *    column_name, user_id, key_id, application_context.
     * 
     * This method encrypts individual values from a typed list (e.g., integers, floats, strings).
     * 
     * @param typed_list The typed list of values to encrypt (variant type supporting multiple data types)
     * @return The encrypted data as a vector of bytes containing the encrypted typed list values
     * @throws InvalidInputException if the input data is invalid or empty
     * @throws DBPSUnsupportedException if the encryption operation is not supported
     */
    virtual std::vector<uint8_t> EncryptValueList(
        const TypedListValues& typed_list) = 0;

    /**
     * Integration point: Decryption function based on encrypted bytes that will be implemented by Protegrity.
     * 
     * This method decrypts the encrypted byte vector containing only the typed list values.
     * 
     * @param encrypted_bytes The encrypted data as a vector of bytes containing only the encrypted typed list
     * @return The decrypted TypedListValues
     * @throws InvalidInputException if the input data is invalid, empty, or corrupted
     * @throws DBPSUnsupportedException if the decryption operation is not supported
     */
    virtual TypedListValues DecryptValueList(
        const std::vector<uint8_t>& encrypted_bytes) = 0;

protected:
    // Context parameters stored from constructor
    std::string key_id_;
    std::string column_name_;
    std::string user_id_;
    std::string application_context_;
};
