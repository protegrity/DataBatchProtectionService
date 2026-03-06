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

#include "bytes_utils.h"
#include "exceptions.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <type_traits>

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <vector>

#include <tcb/span.hpp>


namespace dbps::processing {

// -----------------------------------------------------------------------------
// ByteBuffer class forward declaration
// -----------------------------------------------------------------------------

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
    tcb::span<const uint8_t> GetRawElement(size_t position) const;
    value_type GetElement(size_t position) const;
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

// -----------------------------------------------------------------------------
// Templates for codecs for ByteBuffer
// -----------------------------------------------------------------------------

template <class T, const char* TypeName>
struct PlainValueCodec {
    using value_type = T;
    static constexpr bool is_fixed_sized = true;

    // Compile-time check that the type is trivially copyable (can be copied simply by memcpy)
    static_assert(std::is_trivially_copyable_v<T>,
                  "PlainValueCodec requires trivially copyable T");

    static constexpr std::string_view type_name() noexcept {
        return std::string_view(TypeName);
    }

    constexpr size_t element_size() const noexcept {
        return sizeof(T);
    }

    value_type Decode(tcb::span<const uint8_t> read_span) const {
        if (read_span.size() != sizeof(T)) {
            throw InvalidInputException("Decode: read_span size does not match sizeof(T)");
        }
        T value;
        std::memcpy(&value, read_span.data(), sizeof(T));
        return value;
    }

    void Encode(const value_type& value, tcb::span<uint8_t> write_span) const {
        if (write_span.size() != sizeof(T)) {
            throw InvalidInputException("Encode: write_span size does not match sizeof(T)");
        }
        std::memcpy(write_span.data(), &value, sizeof(T));
    }
};

struct StringFixedSizedCodec {
    using value_type = std::string_view;
    static constexpr bool is_fixed_sized = true;

    explicit StringFixedSizedCodec(size_t element_size_bytes = 0) : element_size_bytes_(element_size_bytes) {
        if (element_size_bytes_ <= 0) {
            throw InvalidInputException("StringFixedSizedCodec requires element_size_bytes > 0");
        }            
    }

    static constexpr std::string_view type_name() noexcept {
        return "string (FIXED_LEN_BYTE_ARRAY)";
    }

    constexpr size_t element_size() const noexcept {
        return element_size_bytes_;
    }

    value_type Decode(tcb::span<const uint8_t> read_span) const {
        if (read_span.size() != element_size_bytes_) {
            throw InvalidInputException("Decode: read_span size does not match element_size_bytes");
        }
        return std::string_view(
            reinterpret_cast<const char*>(read_span.data()),
            read_span.size());
    }

    void Encode(const value_type& value, tcb::span<uint8_t> write_span) const {
        if (write_span.size() != element_size_bytes_) {
            throw InvalidInputException("Encode: write_span size does not match element_size_bytes");
        }
        if (value.size() != write_span.size()) {
            throw InvalidInputException("Encode: value size does not match write_span size");
        }
        std::memcpy(write_span.data(), value.data(), write_span.size());
    }

    private:
        size_t element_size_bytes_;
};

struct StringVariableSizedCodec {
    using value_type = std::string_view;
    static constexpr bool is_fixed_sized = false;

    static constexpr std::string_view type_name() noexcept {
        return "string (BYTE_ARRAY)";
    }

    size_t element_size() const {
        throw InvalidInputException("StringVariableSizedCodec does not have a fixed element size");
    }

    value_type Decode(tcb::span<const uint8_t> read_span) const noexcept {
        return std::string_view(
            reinterpret_cast<const char*>(read_span.data()),
            read_span.size());
    }

    void Encode(const value_type& value, tcb::span<uint8_t> write_span) const {
        if (value.size() != write_span.size()) {
            throw InvalidInputException("Encode: value size does not match write_span size");
        }
        std::memcpy(write_span.data(), value.data(), write_span.size());
    }
};













// -----------------------------------------------------------------------------
// Helper inline functions
// -----------------------------------------------------------------------------

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
template <class Codec>
ByteBuffer<Codec>::ByteBuffer(
    tcb::span<const uint8_t> elements_span,
    size_t prefix_size,
    Codec codec)
    : elements_span_(elements_span),
      num_elements_(0),
      codec_(std::move(codec)),
      element_size_(0),
      prefix_size_(prefix_size),
      is_initialized_from_span_(false) {
    if constexpr (is_fixed_sized) {
        element_size_ = codec_.element_size();
    }
}

// Initializes `num_elements_` and `offsets_` from the span.
// Called in a lazy manner when the buffer is accessed with GetElement, avoiding unnecessary initialization.
template <class Codec>
void ByteBuffer<Codec>::InitializeFromSpan() const {
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
    if constexpr (is_fixed_sized) {
        if (element_size_ <= 0) {
            throw InvalidInputException("Invalid fixed-size buffer: element_size must be greater than zero");
        }
        if ((readable_size % element_size_) != 0) {
            throw InvalidInputException("Malformed fixed-size buffer: buffer does not align with element_size");
        }
        num_elements_ = readable_size / element_size_;
        const size_t expected_payload_bytes = num_elements_ * element_size_;
        if (expected_payload_bytes != readable_size) {
            throw InvalidInputException(
                "Malformed fixed-size buffer: computed payload size does not match readable size");
        }
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

template <class Codec>
void ByteBuffer<Codec>::EnsureInitializedFromSpan() const {
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

template <class Codec>
size_t ByteBuffer<Codec>::EstimateOffsetsReserveCountFromSample(tcb::span<const uint8_t> bytes) {
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

template <class Codec>
size_t ByteBuffer<Codec>::CalculateOffsetOfElement(size_t position) const {
    EnsureInitializedFromSpan();
    if (position >= num_elements_) {
        throw InvalidInputException("Element position out of range during CalculateOffsetOfElement");
    }
    if constexpr (is_fixed_sized) {
        return prefix_size_ + (position * element_size_);
    }
    return offsets_[position];
}

template <class Codec>
tcb::span<const uint8_t> ByteBuffer<Codec>::GetRawElement(size_t position) const {
    EnsureInitializedFromSpan();
    if (position >= num_elements_) {
        throw InvalidInputException("Element position out of range during GetRawElement");
    }
    const size_t offset = CalculateOffsetOfElement(position);
    
    // For fixed-size elements are stored contiguously.
    if constexpr (is_fixed_sized) {
        return elements_span_.subspan(offset, element_size_);
    }

    // For variable-size elements, we need to read the size first [u32 size][element].
    if (offset == kUnsetVariableElementOffset) {
        throw InvalidInputException("Element position has not been written yet");
    }
    const size_t element_size = ReadSizeAt(elements_span_, offset);
    return elements_span_.subspan(offset + kSizePrefixBytes, element_size);
}

template <class Codec>
value_type ByteBuffer<Codec>::GetElement(size_t position) const {
    return codec_.Decode(GetRawElement(position));
}

// -----------------------------------------------------------------------------
// Element span iterator
//
// Allows an alternative read of elements_span_ without need for lazy initialization of offsets_,
// so saving execution time when the traversal of the buffer is strictly sequential.
// This is the most common behavior when reading elements in single threaded mode.
// -----------------------------------------------------------------------------

template <class Codec>
ByteBuffer<Codec>::ConstIterator::ConstIterator(const ByteBuffer<Codec>* buffer, size_t cursor_offset)
    : buffer_(buffer),
      cursor_offset_(cursor_offset),
      elements_span_size_(buffer != nullptr ? buffer->elements_span_.size() : 0u) {}

template <class Codec>
inline size_t ByteBuffer<Codec>::ConstIterator::ReadAndValidateVariableElementSizeAtCursor() const {
    if ((elements_span_size_ - cursor_offset_) < kSizePrefixBytes) {
        throw InvalidInputException("Malformed variable-size buffer: truncated length prefix");
    }
    const size_t current_element_size = ReadSizeAt(buffer_->elements_span_, cursor_offset_);
    const size_t payload_offset = cursor_offset_ + kSizePrefixBytes;
    if ((elements_span_size_ - payload_offset) < current_element_size) {
        throw InvalidInputException("Malformed variable-size buffer: truncated element payload");
    }
    return current_element_size;
}

template <class Codec>
typename ByteBuffer<Codec>::ConstIterator::value_type ByteBuffer<Codec>::ConstIterator::operator*() const {
    if (buffer_ == nullptr || cursor_offset_ >= elements_span_size_) {
        throw InvalidInputException("Cannot dereference ByteBuffer iterator at end position");
    }
    if constexpr (is_fixed_sized) {
        return buffer_->codec_.Decode(buffer_->elements_span_.subspan(cursor_offset_, buffer_->element_size_));
    }

    const size_t current_element_size = ReadAndValidateVariableElementSizeAtCursor();
    const size_t payload_offset = cursor_offset_ + kSizePrefixBytes;
    return buffer_->codec_.Decode(
        buffer_->elements_span_.subspan(payload_offset, current_element_size));
}

template <class Codec>
typename ByteBuffer<Codec>::ConstIterator& ByteBuffer<Codec>::ConstIterator::operator++() {
    if (buffer_ == nullptr || cursor_offset_ >= elements_span_size_) {
        return *this;
    }
    if constexpr (is_fixed_sized) {
        cursor_offset_ += buffer_->element_size_;
        return *this;
    }

    const size_t current_element_size = ReadAndValidateVariableElementSizeAtCursor();
    cursor_offset_ += (kSizePrefixBytes + current_element_size);
    return *this;
}

template <class Codec>
bool ByteBuffer<Codec>::ConstIterator::operator==(const ConstIterator& other) const {
    return buffer_ == other.buffer_ && cursor_offset_ == other.cursor_offset_;
}

template <class Codec>
bool ByteBuffer<Codec>::ConstIterator::operator!=(const ConstIterator& other) const {
    return !(*this == other);
}

template <class Codec>
void ByteBuffer<Codec>::ValidateIteratorReadPreconditions() const {
    if (is_write_buffer_initialized_) {
        throw InvalidInputException("Iterator is only available for read buffers");
    }
    if (elements_span_.size() < prefix_size_) {
        throw InvalidInputException("Malformed buffer: prefix_size exceeds span size");
    }
    if constexpr (is_fixed_sized) {
        if (element_size_ <= 0) {
            throw InvalidInputException("Invalid fixed-size buffer: element_size must be greater than zero");
        }
        const size_t readable_size = elements_span_.size() - prefix_size_;
        if ((readable_size % element_size_) != 0) {
            throw InvalidInputException("Malformed fixed-size buffer: buffer does not align with element_size");
        }
    }
}

template <class Codec>
typename ByteBuffer<Codec>::ConstIterator ByteBuffer<Codec>::begin() const {
    ValidateIteratorReadPreconditions();
    return ConstIterator(this, prefix_size_);
}

template <class Codec>
typename ByteBuffer<Codec>::ConstIterator ByteBuffer<Codec>::end() const {
    ValidateIteratorReadPreconditions();
    return ConstIterator(this, elements_span_.size());
}

// -----------------------------------------------------------------------------
// Constructors and initializers for write buffer
// -----------------------------------------------------------------------------

// Constructor for a new write buffer with fixed-size elements.
template <class Codec>
ByteBuffer<Codec>::ByteBuffer(
    size_t num_elements,
    size_t prefix_size,
    Codec codec)
    : num_elements_(num_elements),
      codec_(std::move(codec)),
      element_size_(0),
      prefix_size_(prefix_size) {
    static_assert(is_fixed_sized, "ByteBuffer constructor for fixed-size elements only.");
    element_size_ = codec_.element_size();
    InitializeForWriteBuffer(0);
}

// Constructor for a new write buffer with variable-size elements.
template <class Codec>
ByteBuffer<Codec>::ByteBuffer(
    size_t num_elements,
    size_t reserved_bytes_hint,
    bool use_reserve_hint,
    size_t prefix_size,
    Codec codec)
    : num_elements_(num_elements),
      codec_(std::move(codec)),
      element_size_(0),
      prefix_size_(prefix_size) {
    static_assert(!is_fixed_sized, "ByteBuffer constructor for variable-size elements only.");
    InitializeForWriteBuffer(use_reserve_hint ? reserved_bytes_hint : 0);
}

// Initializes `write_buffer_`, `offsets_` and `elements_span_`
template <class Codec>
void ByteBuffer<Codec>::InitializeForWriteBuffer(size_t variable_size_reserved_bytes_hint) {
    // Fixed-size elements
    if constexpr (is_fixed_sized) {
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

template <class Codec>
void ByteBuffer<Codec>::SetElement(size_t position, const value_type& element) {
    if (!is_write_buffer_initialized_) {
        throw InvalidInputException("Cannot SetElement: write buffer is not initialized.");
    }

    if (is_write_buffer_finalized_) {
        throw InvalidInputException("Cannot SetElement: write buffer has been finalized");
    }

    if (position >= num_elements_) {
        throw InvalidInputException("Element position out of range during SetElement");
    }

    // For fixed-size elements, we write directly at the fixed offset. No need to re-bind the span.
    if constexpr (is_fixed_sized) {
        const size_t offset = CalculateOffsetOfElement(position);
        auto write_span = tcb::span<uint8_t>(write_buffer_.data() + offset, element_size_);
        codec_.Encode(element, write_span);
        return;
    }

    const size_t element_size = static_cast<size_t>(element.size());

    // Defensive check for unlikely extremely large element size that exceeds uint32.
    if (element_size > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        throw InvalidInputException("Variable-size element payload exceeds uint32 capacity.. Woohhh!!");
    }

    // For variable-size elements, we append the element to the write buffer and update offsets_.
    //
    // We append the element to the write buffer and update offsets_.
    //
    // This can result on orphaned bytes if a position is set multiple times or positions written out of order.
    // This is intentional to allow random writes of elements while the buffer is built.
    // During FinalizeAndTakeBuffer, the buffer is rebuilt to be sequential and orphaned bytes are removed.
    const size_t offset = write_buffer_.size();
    offsets_[position] = offset;
    append_u32_le(write_buffer_, static_cast<uint32_t>(element_size));
    const size_t payload_offset = write_buffer_.size();
    write_buffer_.resize(payload_offset + element_size);
    auto write_span = tcb::span<uint8_t>(write_buffer_.data() + payload_offset, element_size);
    codec_.Encode(element, write_span);

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

template <class Codec>
std::vector<uint8_t> ByteBuffer<Codec>::FinalizeAndTakeBuffer() {
    if (is_write_buffer_finalized_) {
        throw InvalidInputException("FinalizeAndTakeBuffer: write buffer has already been finalized");
    }

    if (!is_write_buffer_initialized_) {
        throw InvalidInputException("FinalizeAndTakeBuffer: write buffer is not initialized");
    }

    // Fixed-size: write_buffer_ is always in element order, transfer ownership directly.
    if constexpr (is_fixed_sized) {
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

template <class Codec>
void ByteBuffer<Codec>::RebindSpanToWriteBuffer() {
    elements_span_ = tcb::span<const uint8_t>(write_buffer_.data(), write_buffer_.size());
}

namespace {
inline constexpr char kI32TypeName[] = "int32";
inline constexpr char kI64TypeName[] = "int64";
inline constexpr char kF32TypeName[] = "float";
inline constexpr char kF64TypeName[] = "double";
} // namespace

template class ByteBuffer<PlainValueCodec<int32_t, kI32TypeName>>;
template class ByteBuffer<PlainValueCodec<int64_t, kI64TypeName>>;
template class ByteBuffer<PlainValueCodec<float, kF32TypeName>>;
template class ByteBuffer<PlainValueCodec<double, kF64TypeName>>;
template class ByteBuffer<StringFixedSizedCodec>;
template class ByteBuffer<StringVariableSizedCodec>;

} // namespace dbps::processing
