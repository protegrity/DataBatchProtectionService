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

#include "dbps_encryptor.h"

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

/**
 * Basic implementation of the DBPSEncryptor interface.
 * 
 * This implementation provides:
 * - Block encryption/decryption using XOR with key_id hash (same as current encryption_sequencer)
 * 
 * This is a simple, default encryption implementation that can be replaced with more
 * sophisticated encryption providers (e.g., Protegrity) in the future.
 */
class DBPS_EXPORT BasicEncryptor : public DBPSEncryptor {
public:
    /**
     * Constructor that initializes the encryptor with context parameters.
     * 
     * @param key_id The encryption key identifier
     * @param column_name The name of the column being encrypted/decrypted
     * @param user_id The user identifier for context
     * @param application_context Additional application context information
     * @param datatype The data type of the column being encrypted/decrypted. 
     *    It is needed for correct type specific parsing during the DecryptValueList call.
     */
    BasicEncryptor(
        const std::string& key_id,
        const std::string& column_name,
        const std::string& user_id,
        const std::string& application_context,
        dbps::external::Type::type datatype)
        : DBPSEncryptor(key_id, column_name, user_id, application_context, datatype) {}

    ~BasicEncryptor() override = default;

    // Block encryption methods
    std::vector<uint8_t> EncryptBlock(const std::vector<uint8_t>& data) override;

    std::vector<uint8_t> DecryptBlock(const std::vector<uint8_t>& data) override;

    // Value encryption methods
    std::vector<uint8_t> EncryptValueList(
        const TypedListValues& typed_list) override;

    TypedListValues DecryptValueList(
        const std::vector<uint8_t>& encrypted_bytes) override;
};

