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

// TODO: Remove these includes when deprecating BasicEncryptor.
#include <cstdint>
#include <string>
#include <tcb/span.hpp>
#include <vector>
#include "../typed_buffer_values.h"
#include "../../common/enums.h"

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

using namespace dbps::processing;

/**
 * TODO: Remove this when deprecating BasicEncryptor.
 * Temporary interface for the XOR encryptor during migration.
 * Keeps XOR implementation independent from DBPSEncryptor while both paths coexist.
 */
class DBPS_EXPORT XorEncryptorInterface {
public:
    XorEncryptorInterface(
        const std::string& key_id,
        const std::string& column_name,
        const std::string& user_id,
        const std::string& application_context,
        dbps::external::Type::type datatype)
        : key_id_(key_id),
          column_name_(column_name),
          user_id_(user_id),
          application_context_(application_context),
          datatype_(datatype) {}

    virtual ~XorEncryptorInterface() = default;

    virtual std::vector<uint8_t> EncryptBlock(tcb::span<const uint8_t> data) = 0;
    virtual std::vector<uint8_t> DecryptBlock(tcb::span<const uint8_t> data) = 0;
    virtual std::vector<uint8_t> EncryptValueList(const TypedValuesBuffer& typed_buffer) = 0;
    virtual TypedValuesBuffer DecryptValueList(tcb::span<const uint8_t> encrypted_bytes) = 0;

protected:
    std::string key_id_;
    std::string column_name_;
    std::string user_id_;
    std::string application_context_;
    dbps::external::Type::type datatype_;
};

/**
 * Basic implementation of the temporary XOR encryptor interface.
 * 
 * This implementation provides:
 * - Block encryption/decryption using XOR with key_id hash (same as current encryption_sequencer)
 * 
 * This is a simple, default encryption implementation that can be replaced with more
 * sophisticated encryption providers (e.g., Protegrity) in the future.
 */
class DBPS_EXPORT BasicXorEncryptor : public XorEncryptorInterface {
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
    BasicXorEncryptor(
        const std::string& key_id,
        const std::string& column_name,
        const std::string& user_id,
        const std::string& application_context,
        dbps::external::Type::type datatype)
        : XorEncryptorInterface(key_id, column_name, user_id, application_context, datatype) {}

    ~BasicXorEncryptor() override = default;

    // Block encryption methods
    std::vector<uint8_t> EncryptBlock(tcb::span<const uint8_t> data) override;

    std::vector<uint8_t> DecryptBlock(tcb::span<const uint8_t> data) override;

    // Value encryption methods
    std::vector<uint8_t> EncryptValueList(const TypedValuesBuffer& typed_buffer) override;

    TypedValuesBuffer DecryptValueList(tcb::span<const uint8_t> encrypted_bytes) override;
};

