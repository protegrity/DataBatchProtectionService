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

#include "byte_buffer.h"

#include "bytes_utils.h"
#include "exceptions.h"
#include <cstring>
#include <limits>

namespace dbps::processing {

namespace {
// Reads the element size at the given offset.
inline size_t ReadElementSizeAt(tcb::span<const uint8_t> bytes, size_t offset) {
    return static_cast<size_t>(read_u32_le(bytes, offset));
}
}

// -----------------------------------------------------------------------------
// Constructors and initializers for read-only buffer
// -----------------------------------------------------------------------------

// Constructor for read-only buffer with fixed-size elements.
ByteBuffer::ByteBuffer(
    tcb::span<const uint8_t> elements_span,
    size_t element_size)
    : elements_span_(elements_span),
      has_fixed_sized_elements_(true),
      element_size_(element_size) {
    InitializeFromSpan();
}

// Constructor for read-only buffer with variable-size elements.
ByteBuffer::ByteBuffer(
    tcb::span<const uint8_t> elements_span)
    : elements_span_(elements_span),
      has_fixed_sized_elements_(false),
      element_size_(0) {
    InitializeFromSpan();
}

// Initializes `num_elements_` and `offsets_` from the span.
void ByteBuffer::InitializeFromSpan() {
    // No elements to index. Initialize with empty values.
    if (elements_span_.empty()) {
        num_elements_ = 0;
        offsets_.clear();
        return;
    }

    // Fixed-size layout has implicit offsets from index * element_size.
    // We validate shape and derive element count. No need to store offsets.
    if (has_fixed_sized_elements_) {
        if (element_size_ <= 0) {
            throw InvalidInputException("Invalid fixed-size buffer: element_size must be greater than zero");
        }
        if ((elements_span_.size() % element_size_) != 0) {
            throw InvalidInputException("Malformed fixed-size buffer: size is not divisible by element_size");
        }
        num_elements_ = elements_span_.size() / element_size_;
        offsets_.clear();
        return;
    }

    // Variable-size layout stores [u32 size][element value] back-to-back.
    // First pass counts elements and validates shape.
    size_t cursor = 0;
    size_t count = 0;
    while (cursor < elements_span_.size()) {
        if (elements_span_.size() - cursor < 4) {
            throw InvalidInputException("Malformed variable-size buffer: truncated length prefix");
        }
        const size_t current_element_size = ReadElementSizeAt(elements_span_, cursor);
        cursor += 4;
        if (elements_span_.size() - cursor < current_element_size) {
            throw InvalidInputException("Malformed variable-size buffer: truncated element payload");
        }
        cursor += current_element_size;
        ++count;
    }

    // Set the number of elements.
    num_elements_ = count;

    // Set the offsets for variable-size elements on the second pass.
    offsets_.clear();
    offsets_.reserve(num_elements_);
    cursor = 0;
    while (cursor < elements_span_.size()) {
        offsets_.push_back(cursor);
        const size_t current_element_size = ReadElementSizeAt(elements_span_, cursor);
        cursor += 4 + current_element_size;
    }
}

// -----------------------------------------------------------------------------
// Span reader methods
// -----------------------------------------------------------------------------

size_t ByteBuffer::GetOffsetOfElement(size_t position) const {
    if (position >= num_elements_) {
        throw InvalidInputException("Element position out of range during GetOffsetOfElement");
    }
    if (has_fixed_sized_elements_) {
        return position * element_size_;
    }
    return offsets_[position];
}

tcb::span<const uint8_t> ByteBuffer::getElement(size_t position) const {
    if (position >= num_elements_) {
        throw InvalidInputException("Element position out of range during getElement");
    }
    const size_t offset = GetOffsetOfElement(position);
    
    // For fixed-size elemments are stored contiguously.
    if (has_fixed_sized_elements_) {
        return elements_span_.subspan(offset, element_size_);
    }

    // For variable-size elements, we need to read the size first [u32 size][element].
    const size_t element_size = ReadElementSizeAt(elements_span_, offset);
    return elements_span_.subspan(offset + 4, element_size);
}

// -----------------------------------------------------------------------------
// Constructors and initializers for write buffer
// -----------------------------------------------------------------------------

// Constructor for a new write buffer with fixed-size elements.
ByteBuffer::ByteBuffer(
    size_t num_elements,
    size_t element_size)
    : num_elements_(num_elements),
      has_fixed_sized_elements_(true),
      element_size_(element_size) {
    InitializeForWriteBuffer(0);
}

// Constructor for a new write buffer with variable-size elements.
ByteBuffer::ByteBuffer(
    size_t num_elements,
    size_t reserved_bytes_hint,
    bool use_reserve_hint)
    : num_elements_(num_elements),
      has_fixed_sized_elements_(false),
      element_size_(0) {
    InitializeForWriteBuffer(use_reserve_hint ? reserved_bytes_hint : 0);
}

// Initializes `write_buffer_`, `offsets_` and `elements_span_`
void ByteBuffer::InitializeForWriteBuffer(size_t variable_size_reserved_bytes_hint) {

    // Fixed-size elements
    if (has_fixed_sized_elements_) {
        if (element_size_ <= 0) {
            throw InvalidInputException("Invalid fixed-size buffer: element_size must be greater than zero");
        }

        // write_buffer can be allocated to precise size since the element size and number of elements are known.
        // We initialize it to 0s to have random-ish access during writes.
        const size_t fixed_size_total_bytes = num_elements_ * element_size_;
        write_buffer_.clear();
        write_buffer_.resize(fixed_size_total_bytes, static_cast<uint8_t>(0));

        // offsets_ are not used for fixed-size elements.
        offsets_.clear();

        // elements_span_ is re-bound to the write buffer.
        RebindSpanToWriteBuffer();
        return;
    }

    // Variable-size elements

    // Reserve write_buffer to at least the size of the prefix [u32 size] bytes for all elements,
    //  and use a larger reserved-bytes hint if given as a best guess to reduce reallocations.
    // write_buffer is not initialized to anything since we will be appending to it during setElement, just reserving capacity.
    const size_t min_required_prefix_bytes = num_elements_ * static_cast<size_t>(4);
    const size_t variable_size_reserved_bytes =
        (variable_size_reserved_bytes_hint < min_required_prefix_bytes)
            ? min_required_prefix_bytes
            : variable_size_reserved_bytes_hint;
    write_buffer_.clear();
    write_buffer_.reserve(variable_size_reserved_bytes);

    // offsets_ is initialized so the vector is fully allocated and have random-ish access during writes.
    offsets_.clear();
    offsets_.resize(num_elements_);

    // elements_span_ is re-bound to the write buffer.
    RebindSpanToWriteBuffer();
}

// -----------------------------------------------------------------------------
// Buffer writer methods
// -----------------------------------------------------------------------------

void ByteBuffer::setElement(size_t position, tcb::span<const uint8_t> element) {
    if (position >= num_elements_) {
        throw InvalidInputException("Element position out of range during setElement");
    }

    if (write_buffer_.empty()) {
        throw InvalidInputException("Cannot set element: write buffer is not initialized");
    }

    // For fixed-size elements, we write the element to buffer at the offset. No need to re-bind the span.
    if (has_fixed_sized_elements_) {
        if (element.size() != element_size_) {
            throw InvalidInputException("Fixed-size element payload size mismatch");
        }
        const size_t offset = GetOffsetOfElement(position);
        std::memcpy(write_buffer_.data() + offset, element.data(), element_size_);
        return;
    }

    // Defensive check for unlikely extremely large element size that exceeds uint32.
    if (element.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        throw InvalidInputException("Variable-size element payload exceeds uint32 capacity.. Woohhh!!");
    }

    // For variable-size elements, we append the element to the write buffer and update offsets_.
    const size_t offset = write_buffer_.size();
    offsets_[position] = offset;
    append_u32_le(write_buffer_, static_cast<uint32_t>(element.size()));
    write_buffer_.insert(write_buffer_.end(), element.begin(), element.end());

    RebindSpanToWriteBuffer();
}

void ByteBuffer::RebindSpanToWriteBuffer() {
    elements_span_ = tcb::span<const uint8_t>(write_buffer_.data(), write_buffer_.size());
}

} // namespace dbps::processing
