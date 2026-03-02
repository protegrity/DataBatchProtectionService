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

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#include <tcb/span.hpp>

namespace dbps::processing {

class ByteBuffer {
public:
    // Constructor for read-only buffer with fixed-size elements.
    // Elements are stored contiguously in the span.
    ByteBuffer(
        tcb::span<const uint8_t> elements_span,
        size_t element_size);

    // Constructor for read-only buffer with variable-size elements.
    // Elements are encoded as [u32 size][element value] contiguously in the span.
    ByteBuffer(
        tcb::span<const uint8_t> elements_span);

    // Constructor for a new write buffer with fixed-size elements.
    ByteBuffer(
        size_t num_elements,
        size_t element_size);
    
    // Constructor for a new write buffer with variable-size elements.
    ByteBuffer(
        size_t num_elements,
        size_t reserved_bytes_hint,
        bool use_reserve_hint);

    // Get and set elements by position
    tcb::span<const uint8_t> GetElement(size_t position) const;
    void SetElement(size_t position, tcb::span<const uint8_t> element);

    // Finalizes the write path and transfers the resulting buffer ownership.
    std::vector<uint8_t> FinalizeAndTakeBuffer();

protected:
    // Helper for reserve heuristics in variable-size parsing.
    static size_t EstimateOffsetsReserveCountFromSample(tcb::span<const uint8_t> bytes);

    // Helper for calculating the offset of an element by position.
    size_t CalculateOffsetOfElement(size_t position) const;

    // Variables for span elements reading
    tcb::span<const uint8_t> elements_span_;
    mutable size_t num_elements_;
    bool has_fixed_sized_elements_;
    
    // Variables for determining offset of elements.
    size_t element_size_;                   // for fixed-size elements
    mutable std::vector<size_t> offsets_;   // for variable-size elements

    // Variables for write buffer.
    std::vector<uint8_t> write_buffer_;

    // Variable for sequential variable-size writes.
    // Tracks next expected position for sequential variable-size writes.
    // Value is invalidated to kUnsetVariableElementOffset once order is violated.
    size_t next_expected_write_position_ = 0;

private:
    // Initialization methods and flags for read-only buffer
    void InitializeFromSpan() const;
    void EnsureInitializedFromSpan() const;
    mutable bool is_initialized_from_span_ = false;

    // Initialization methods and flags for write buffer
    void InitializeForWriteBuffer(size_t variable_size_reserved_bytes_hint);
    void RebindSpanToWriteBuffer();
    bool is_write_buffer_initialized_ = false;
    bool is_write_buffer_finalized_ = false;    
};

inline constexpr size_t kUnsetVariableElementOffset = std::numeric_limits<size_t>::max();
inline constexpr size_t kSizePrefixBytes = sizeof(uint32_t);  // [u32 size] prefix for variable-size elements.

} // namespace dbps::processing
