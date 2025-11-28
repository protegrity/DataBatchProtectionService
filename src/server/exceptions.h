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

#include <stdexcept>
#include <string>

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

/**
 * Base class for all DBPS server exceptions.
 * Provides a common base for catching all DBPS-related exceptions.
 */
class DBPS_EXPORT DBPSBaseException : public std::runtime_error {
public:
    explicit DBPSBaseException(const std::string& message) : std::runtime_error(message) {}
};

/**
 * Exception thrown when an operation or feature is not supported.
 */
class DBPS_EXPORT DBPSUnsupportedException : public DBPSBaseException {
public:
    explicit DBPSUnsupportedException(const std::string& message) : DBPSBaseException(message) {}
};

/**
 * Exception thrown when input data is invalid or malformed.
 */
class DBPS_EXPORT InvalidInputException : public DBPSBaseException {
public:
    explicit InvalidInputException(const std::string& message) : DBPSBaseException(message) {}
};

