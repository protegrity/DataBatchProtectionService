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
#include <iterator>
#include <limits>
#include <vector>

#include <tcb/span.hpp>

namespace dbps::processing {

template <class Codec>
class ByteBuffer {
public:
    using value_type = typename Codec::value_type;
    static constexpr bool is_fixed_sized = Codec::is_fixed_sized;

    // Constructor for read-only buffer for both fixed-sized and variable-sized elements.
    // Elements are stored contiguously in the span.
    ByteBuffer(
        tcb::span<const uint8_t> elements_span,
        size_t prefix_size = 0,
        Codec codec = Codec{});

    // Constructor for a new write buffer with both fixed-sized and variable-sized elements.
    ByteBuffer(
        size_t num_elements,
        size_t prefix_size = 0,
        Codec codec = Codec{});
    
    // Constructor for a new write buffer with variable-size elements.
    ByteBuffer(
        size_t num_elements,
        size_t reserved_bytes_hint,
        bool use_reserve_hint,
        size_t prefix_size = 0,
        Codec codec = Codec{});

    // Get and set elements by position with type access from Codec
    value_type GetElement(size_t position) const;
    tcb::span<const uint8_t> GetRawElement(size_t position) const;
    void SetElement(size_t position, const value_type& element);

    // Finalizes the write path and transfers the resulting buffer ownership.
    std::vector<uint8_t> FinalizeAndTakeBuffer();

    // Iterator for read-only elements.
    class ConstIterator {
        public:
            // Iterator traits consumed indirectly by STL iterator machinery.
            using iterator_category = std::forward_iterator_tag;
            using value_type = typename ByteBuffer::value_type;
            using difference_type = std::ptrdiff_t;
            using pointer = void;
            using reference = value_type;
    
            // Basic forward-iterator operations over encoded elements in elements_span_.
            ConstIterator(const ByteBuffer* buffer, size_t cursor_offset);
            value_type operator*() const;
            ConstIterator& operator++();
            bool operator==(const ConstIterator& other) const;
            bool operator!=(const ConstIterator& other) const;
    
        private:
            size_t ReadAndValidateVariableElementSizeAtCursor() const;

            const ByteBuffer* buffer_ = nullptr;
            size_t cursor_offset_ = 0;
            size_t elements_span_size_ = 0;
        };
    
    // Methods used by the STL iterator machinery to iterate over the buffer.
    ConstIterator begin() const;
    ConstIterator end() const;

protected:
    // Helper for reserve heuristics in variable-size parsing.
    static size_t EstimateOffsetsReserveCountFromSample(tcb::span<const uint8_t> bytes);

    // Helper for calculating the offset of an element by position.
    size_t CalculateOffsetOfElement(size_t position) const;

    // Helper to validate the preconditions for reading the buffer with an iterator.
    void ValidateIteratorReadPreconditions() const;

    // Variables for span elements reading
    tcb::span<const uint8_t> elements_span_;
    mutable size_t num_elements_;
    Codec codec_;
    
    // Variables for determining offset of elements.
    size_t prefix_size_ = 0;
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

// Constant to mark an offset value as unset.
inline constexpr size_t kUnsetVariableElementOffset = std::numeric_limits<size_t>::max();

// Constant for the size of the [u32 size] prefix for variable-size elements.
inline constexpr size_t kSizePrefixBytes = sizeof(uint32_t);

} // namespace dbps::processing
