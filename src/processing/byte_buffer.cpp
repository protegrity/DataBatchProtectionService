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
#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>

namespace dbps::processing {

namespace {
// Reads the element size at the given offset.
inline size_t ReadSizeAt(tcb::span<const uint8_t> bytes, size_t offset) {
    return static_cast<size_t>(read_u32_le(bytes, offset));
}
}

// -----------------------------------------------------------------------------
// Constructors and initializers for read-only buffer
// -----------------------------------------------------------------------------

// Constructor for read-only buffer with fixed-size elements.
ByteBuffer::ByteBuffer(
    tcb::span<const uint8_t> elements_span,
    size_t element_size,
    size_t prefix_size)
    : elements_span_(elements_span),
      num_elements_(0),
      has_fixed_sized_elements_(true),
      element_size_(element_size),
      prefix_size_(prefix_size),
      is_initialized_from_span_(false) {}

// Constructor for read-only buffer with variable-size elements.
ByteBuffer::ByteBuffer(
    tcb::span<const uint8_t> elements_span,
    size_t prefix_size)
    : elements_span_(elements_span),
      num_elements_(0),
      has_fixed_sized_elements_(false),
      element_size_(0),
      prefix_size_(prefix_size),
      is_initialized_from_span_(false) {}

// Initializes `num_elements_` and `offsets_` from the span.
// Called in a lazy manner when the buffer is accessed with GetElement, avoiding unnecessary initialization.
void ByteBuffer::InitializeFromSpan() const {
    if (elements_span_.size() < prefix_size_) {
        throw InvalidInputException("Malformed buffer: prefix_size exceeds span size");
    }

    const size_t readable_size = elements_span_.size() - prefix_size_;

    // No elements to index. Initialize with empty values.
    if (readable_size == 0) {
        num_elements_ = 0;
        offsets_.clear();
        is_initialized_from_span_ = true;
        return;
    }

    // Fixed-size layout has implicit offsets from index * element_size.
    // We validate shape and derive element count. No need to store offsets.
    if (has_fixed_sized_elements_) {
        if (element_size_ <= 0) {
            throw InvalidInputException("Invalid fixed-size buffer: element_size must be greater than zero");
        }
        if ((readable_size % element_size_) != 0) {
            throw InvalidInputException("Malformed fixed-size buffer: buffer does not align with element_size");
        }
        num_elements_ = readable_size / element_size_;
        offsets_.clear();
        is_initialized_from_span_ = true;
        return;
    }

    // Variable-size layout stores [u32 size][element value] back-to-back.
    // Single pass validates shape and captures per-element prefix offsets.
    offsets_.clear();
    offsets_.reserve(EstimateOffsetsReserveCountFromSample(elements_span_.subspan(prefix_size_)));
    size_t cursor = prefix_size_;
    while (cursor < elements_span_.size()) {
        if (elements_span_.size() - cursor < kSizePrefixBytes) {
            throw InvalidInputException("Malformed variable-size buffer: truncated length prefix");
        }
        offsets_.push_back(cursor);
        const size_t current_element_size = ReadSizeAt(elements_span_, cursor);
        cursor += kSizePrefixBytes;
        if (elements_span_.size() - cursor < current_element_size) {
            throw InvalidInputException("Malformed variable-size buffer: truncated element payload");
        }
        cursor += current_element_size;
    }
    num_elements_ = offsets_.size();
    is_initialized_from_span_ = true;
}

void ByteBuffer::EnsureInitializedFromSpan() const {
    // If the span is already initialized, skip it.
    if (is_initialized_from_span_) {
        return;
    }
    // If the write buffer is initialized, we don't need to initialize from the span.
    if (is_write_buffer_initialized_) {
        return;
    }
    InitializeFromSpan();
}

size_t ByteBuffer::EstimateOffsetsReserveCountFromSample(tcb::span<const uint8_t> bytes) {
    if (bytes.empty())
        return 0;

    // Sample the first 10 elements to estimate the total element count.
    size_t cursor = 0;
    size_t sampled_elements = 0;
    while (cursor < bytes.size() && sampled_elements < 10) {
        if (bytes.size() - cursor < kSizePrefixBytes) {
            throw InvalidInputException("Malformed variable-size buffer: truncated length prefix");
        }
        const size_t current_element_size = ReadSizeAt(bytes, cursor);
        cursor += kSizePrefixBytes;
        if (bytes.size() - cursor < current_element_size) {
            throw InvalidInputException("Malformed variable-size buffer: truncated element payload");
        }
        cursor += current_element_size;
        ++sampled_elements;
    }

    // If no elements were sampled or the cursor didn't move, it means the buffer is empty. So return 0.
    if (sampled_elements == 0 || cursor == 0)
        return 0;

    // If sampling consumed the full buffer (<= sample window), we already know the exact count.
    if (cursor == bytes.size())
        return sampled_elements;

    // Estimate total element count from sample density: (sampled_elements / sampled_bytes) * total_bytes.
    // - sampled_elements / sampled_bytes gives "elements per byte" in the sampled prefix,
    // - then multiplying by total_bytes extrapolates a full-buffer estimate.
    const long double estimated =
        (static_cast<long double>(bytes.size()) * static_cast<long double>(sampled_elements)) /
        static_cast<long double>(cursor);
    const size_t estimated_count = static_cast<size_t>(std::ceil(estimated));
    const size_t estimated_with_headroom =
        static_cast<size_t>(std::ceil(static_cast<long double>(estimated_count) * 1.1L));

    // If the count of sampled elements is more than the estimated, conservatively return actual count.
    return std::max(estimated_with_headroom, sampled_elements);
}

// -----------------------------------------------------------------------------
// Element span reader methods
// -----------------------------------------------------------------------------

size_t ByteBuffer::CalculateOffsetOfElement(size_t position) const {
    EnsureInitializedFromSpan();
    if (position >= num_elements_) {
        throw InvalidInputException("Element position out of range during CalculateOffsetOfElement");
    }
    if (has_fixed_sized_elements_) {
        return prefix_size_ + (position * element_size_);
    }
    return offsets_[position];
}

tcb::span<const uint8_t> ByteBuffer::GetElement(size_t position) const {
    EnsureInitializedFromSpan();
    if (position >= num_elements_) {
        throw InvalidInputException("Element position out of range during GetElement");
    }
    const size_t offset = CalculateOffsetOfElement(position);
    
    // For fixed-size elemments are stored contiguously.
    if (has_fixed_sized_elements_) {
        return elements_span_.subspan(offset, element_size_);
    }

    // For variable-size elements, we need to read the size first [u32 size][element].
    if (offset == kUnsetVariableElementOffset) {
        throw InvalidInputException("Element position has not been written yet");
    }
    const size_t element_size = ReadSizeAt(elements_span_, offset);
    return elements_span_.subspan(offset + kSizePrefixBytes, element_size);
}

// -----------------------------------------------------------------------------
// Elemment span iterator
//
// Allows an alternative read of elements_span_ without need for lazy initialization of offsets_,
// so saving execution time when the traversal of the buffer is strictly sequential.
// This is the most common behavior when reading elements in single threaded mode.
// -----------------------------------------------------------------------------

ByteBuffer::ConstIterator::ConstIterator(const ByteBuffer* buffer, size_t cursor_offset)
    : buffer_(buffer), cursor_offset_(cursor_offset) {}

void ByteBuffer::ConstIterator::ValidateFixedSizeElementAtCursor() const {
    if (buffer_->element_size_ <= 0) {
        throw InvalidInputException("Invalid fixed-size buffer: element_size must be greater than zero");
    }
    if ((buffer_->elements_span_.size() - cursor_offset_) < buffer_->element_size_) {
        throw InvalidInputException("Malformed fixed-size buffer: truncated element payload");
    }
}

size_t ByteBuffer::ConstIterator::ReadAndValidateVariableElementSizeAtCursor() const {
    if ((buffer_->elements_span_.size() - cursor_offset_) < kSizePrefixBytes) {
        throw InvalidInputException("Malformed variable-size buffer: truncated length prefix");
    }
    const size_t current_element_size = ReadSizeAt(buffer_->elements_span_, cursor_offset_);
    const size_t payload_offset = cursor_offset_ + kSizePrefixBytes;
    if ((buffer_->elements_span_.size() - payload_offset) < current_element_size) {
        throw InvalidInputException("Malformed variable-size buffer: truncated element payload");
    }
    return current_element_size;
}

ByteBuffer::ConstIterator::value_type ByteBuffer::ConstIterator::operator*() const {
    if (buffer_ == nullptr || cursor_offset_ >= buffer_->elements_span_.size()) {
        throw InvalidInputException("Cannot dereference ByteBuffer iterator at end position");
    }
    if (buffer_->has_fixed_sized_elements_) {
        ValidateFixedSizeElementAtCursor();
        return buffer_->elements_span_.subspan(cursor_offset_, buffer_->element_size_);
    }

    const size_t current_element_size = ReadAndValidateVariableElementSizeAtCursor();
    const size_t payload_offset = cursor_offset_ + kSizePrefixBytes;
    return buffer_->elements_span_.subspan(payload_offset, current_element_size);
}

ByteBuffer::ConstIterator& ByteBuffer::ConstIterator::operator++() {
    if (buffer_ == nullptr || cursor_offset_ >= buffer_->elements_span_.size()) {
        return *this;
    }
    if (buffer_->has_fixed_sized_elements_) {
        ValidateFixedSizeElementAtCursor();
        cursor_offset_ += buffer_->element_size_;
        return *this;
    }

    const size_t current_element_size = ReadAndValidateVariableElementSizeAtCursor();
    cursor_offset_ += (kSizePrefixBytes + current_element_size);
    return *this;
}

bool ByteBuffer::ConstIterator::operator==(const ConstIterator& other) const {
    return buffer_ == other.buffer_ && cursor_offset_ == other.cursor_offset_;
}

bool ByteBuffer::ConstIterator::operator!=(const ConstIterator& other) const {
    return !(*this == other);
}

void ByteBuffer::ValidateIteratorReadPreconditions() const {
    if (is_write_buffer_initialized_) {
        throw InvalidInputException("Iterator is only available for read buffers");
    }
    if (elements_span_.size() < prefix_size_) {
        throw InvalidInputException("Malformed buffer: prefix_size exceeds span size");
    }
    if (has_fixed_sized_elements_) {
        if (element_size_ <= 0) {
            throw InvalidInputException("Invalid fixed-size buffer: element_size must be greater than zero");
        }
        const size_t readable_size = elements_span_.size() - prefix_size_;
        if ((readable_size % element_size_) != 0) {
            throw InvalidInputException("Malformed fixed-size buffer: buffer does not align with element_size");
        }
    }
}

ByteBuffer::ConstIterator ByteBuffer::begin() const {
    ValidateIteratorReadPreconditions();
    return ConstIterator(this, prefix_size_);
}

ByteBuffer::ConstIterator ByteBuffer::end() const {
    ValidateIteratorReadPreconditions();
    return ConstIterator(this, elements_span_.size());
}

// -----------------------------------------------------------------------------
// Constructors and initializers for write buffer
// -----------------------------------------------------------------------------

// Constructor for a new write buffer with fixed-size elements.
ByteBuffer::ByteBuffer(
    size_t num_elements,
    size_t element_size,
    size_t prefix_size)
    : num_elements_(num_elements),
      has_fixed_sized_elements_(true),
      element_size_(element_size),
      prefix_size_(prefix_size) {
    InitializeForWriteBuffer(0);
}

// Constructor for a new write buffer with variable-size elements.
ByteBuffer::ByteBuffer(
    size_t num_elements,
    size_t reserved_bytes_hint,
    bool use_reserve_hint,
    size_t prefix_size)
    : num_elements_(num_elements),
      has_fixed_sized_elements_(false),
      element_size_(0),
      prefix_size_(prefix_size) {
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
        const size_t fixed_size_total_bytes = prefix_size_ + (num_elements_ * element_size_);
        write_buffer_.clear();
        write_buffer_.resize(fixed_size_total_bytes, static_cast<uint8_t>(0));
        is_write_buffer_initialized_ = true;

        // offsets_ are not used for fixed-size elements.
        offsets_.clear();

        // elements_span_ is re-bound to the write buffer.
        RebindSpanToWriteBuffer();
        return;
    }

    // Variable-size elements

    // Reserve write_buffer to at least the size of the prefix [u32 size] bytes for all elements,
    //  and use a larger reserved-bytes hint if given as a best guess to reduce reallocations.
    // write_buffer is not initialized to anything since we will be appending to it during SetElement, just reserving capacity.
    const size_t min_required_record_bytes = num_elements_ * kSizePrefixBytes;
    const size_t variable_size_reserved_bytes =
        prefix_size_ + std::max(variable_size_reserved_bytes_hint, min_required_record_bytes);
    write_buffer_.clear();
    write_buffer_.resize(prefix_size_, static_cast<uint8_t>(0));
    write_buffer_.reserve(variable_size_reserved_bytes);
    is_write_buffer_initialized_ = true;

    // offsets_ is initialized so the vector is fully allocated and have random-ish access during writes.
    offsets_.clear();
    offsets_.resize(num_elements_, kUnsetVariableElementOffset);

    // next_expected_sequential_position_ is initialized to 0 for sequential write checking.
    next_expected_write_position_ = 0;

    // elements_span_ is re-bound to the write buffer.
    RebindSpanToWriteBuffer();
}

// -----------------------------------------------------------------------------
// Buffer writer methods
// -----------------------------------------------------------------------------

void ByteBuffer::SetElement(size_t position, tcb::span<const uint8_t> element) {
    if (!is_write_buffer_initialized_) {
        throw InvalidInputException("Cannot SetElement: write buffer is not initialized.");
    }

    if (is_write_buffer_finalized_) {
        throw InvalidInputException("Cannot SetElement: write buffer has been finalized");
    }

    if (position >= num_elements_) {
        throw InvalidInputException("Element position out of range during SetElement");
    }

    // For fixed-size elements, we write the element to buffer at the offset. No need to re-bind the span.
    if (has_fixed_sized_elements_) {
        if (element.size() != element_size_) {
            throw InvalidInputException("Fixed-size element payload size mismatch");
        }
        const size_t offset = CalculateOffsetOfElement(position);
        std::memcpy(write_buffer_.data() + offset, element.data(), element_size_);
        return;
    }

    // Defensive check for unlikely extremely large element size that exceeds uint32.
    if (element.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        throw InvalidInputException("Variable-size element payload exceeds uint32 capacity.. Woohhh!!");
    }

    // For variable-size elements, we append the element to the write buffer and update offsets_.
    //
    // This can result on orphaned bytes if a position is set multiple times or positions written out of order.
    // This is intentional to allow random writes of elements while the buffer is built.
    // During FinalizeAndTakeBuffer, the buffer is rebuilt to be sequential and orphaned bytes are removed.
    const size_t offset = write_buffer_.size();
    offsets_[position] = offset;
    append_u32_le(write_buffer_, static_cast<uint32_t>(element.size()));
    write_buffer_.insert(write_buffer_.end(), element.begin(), element.end());  // Appends at the end of the buffer.

    // Update next_expected_write_position_ for sequential write checking.
    if (next_expected_write_position_ != kUnsetVariableElementOffset) {
        if (position == next_expected_write_position_) {
            next_expected_write_position_ += 1;
        } else {
            next_expected_write_position_ = kUnsetVariableElementOffset;
        }
    }

    RebindSpanToWriteBuffer();
}

std::vector<uint8_t> ByteBuffer::FinalizeAndTakeBuffer() {
    if (is_write_buffer_finalized_) {
        throw InvalidInputException("FinalizeAndTakeBuffer: write buffer has already been finalized");
    }

    if (!is_write_buffer_initialized_) {
        throw InvalidInputException("FinalizeAndTakeBuffer: write buffer is not initialized");
    }

    // Fixed-size: write_buffer_ is always in element order, transfer ownership directly.
    if (has_fixed_sized_elements_) {
        is_write_buffer_finalized_ = true;
        return std::move(write_buffer_);
    }

    // For variable-size when all elements were written exactly once and in sequential order,
    // we can skip out-of-order or fragmentation checks.  This is the fast path.
    // This is the most common behavior when writing elements in single threaded mode.
    if (next_expected_write_position_ == num_elements_) {
        if (num_elements_ > 0) {
            const size_t last_element_offset = offsets_[num_elements_ - 1];
            const size_t last_element_size = ReadSizeAt(elements_span_, last_element_offset);
            const size_t logical_size = last_element_offset + kSizePrefixBytes + last_element_size;
            if (logical_size != write_buffer_.size()) {
                throw InvalidInputException("FinalizeAndTakeBuffer: trailing bytes detected beyond last element");
            }
        }
        is_write_buffer_finalized_ = true;
        return std::move(write_buffer_);
    }

    // For variable-size, when elements are written out of order, assume the buffer is fragmented and potentially with orphaned bytes
    // The buffer is validated and rebuilt into an ordered compact buffer in one pass.
    std::vector<uint8_t> result;
    result.reserve(write_buffer_.size());
    // Copy the prefix bytes at the beginning of the result.
    result.insert(
        result.end(),
        write_buffer_.begin(),
        write_buffer_.begin() + static_cast<std::ptrdiff_t>(prefix_size_));
    for (size_t i = 0; i < num_elements_; ++i) {
        const size_t element_offset = offsets_[i];
        if (element_offset == kUnsetVariableElementOffset) {
            throw InvalidInputException("Cannot finalize variable-size buffer: not all elements were written");
        }
        if (element_offset > write_buffer_.size() || (write_buffer_.size() - element_offset) < kSizePrefixBytes) {
            throw InvalidInputException("Cannot finalize variable-size buffer: invalid element offset");
        }

        const size_t element_size = ReadSizeAt(elements_span_, element_offset);
        if (element_size > (write_buffer_.size() - element_offset - kSizePrefixBytes)) {
            throw InvalidInputException("Cannot finalize variable-size buffer: malformed element payload");
        }

        const size_t record_size = kSizePrefixBytes + element_size;
        result.insert(
            result.end(),
            write_buffer_.data() + element_offset,
            write_buffer_.data() + element_offset + record_size);
    }

    // Defrag path returns a new buffer; release the original fragmented write buffer.
    write_buffer_.clear();
    write_buffer_.shrink_to_fit();
    is_write_buffer_initialized_ = false;
    is_write_buffer_finalized_ = true;
    
    return result;
}

void ByteBuffer::RebindSpanToWriteBuffer() {
    elements_span_ = tcb::span<const uint8_t>(write_buffer_.data(), write_buffer_.size());
}

} // namespace dbps::processing
