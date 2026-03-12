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

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <vector>

#include <tcb/span.hpp>

#include "bytes_utils.h"
#include "exceptions.h"

namespace dbps::processing {

// -----------------------------------------------------------------------------
// ByteBuffer class forward declaration
// -----------------------------------------------------------------------------

template <class Codec>
class ByteBuffer {
public:
    using value_type = typename Codec::value_type;
    static constexpr bool is_fixed_sized = Codec::is_fixed_sized;
    static constexpr std::string_view type_name() noexcept { return Codec::type_name(); }

    // Constructor for read-only buffer for both fixed-sized and variable-sized elements.
    // Elements are stored contiguously in the span.
    ByteBuffer(
        tcb::span<const uint8_t> elements_span,
        size_t prefix_size = 0,
        Codec codec = Codec{});

    // Constructor for a new write buffer with fixed-sized elements.    
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
    tcb::span<uint8_t> GetWritableRawElement(size_t position, size_t payload_size);
    void SetElement(size_t position, const value_type& element);
    void SetRawElement(size_t position, tcb::span<const uint8_t> raw);

    // Getters for immediately available properties.
    size_t GetRawBufferSize() const { return elements_span_size_; }
    size_t GetElementSize() const { return codec_.element_size(); }

    // Get the number of elements in the buffer.
    size_t GetNumElements() const;

    // Finalizes the write path and transfers the resulting buffer ownership.
    std::vector<uint8_t> FinalizeAndTakeBuffer();

    // Iterator for read-only elements returning raw bytes.
    tcb::span<const uint8_t> ElementsIteratorNext() const;

    // Iterator for read-only elements returning a `value_type`
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
    
        protected:
            size_t ReadAndValidateVariableElementSizeAtCursor() const;
            tcb::span<const uint8_t> RawSpanAtCursor() const;

            const ByteBuffer* buffer_ = nullptr;
            size_t cursor_offset_ = 0;
            size_t elements_span_size_ = 0;
            mutable size_t current_element_size_ = 0;
        };
    // Methods used by the STL iterator machinery to iterate over the buffer.
    ConstIterator begin() const;
    ConstIterator end() const;

    // Iterator for read-only elements returning raw bytes.
    // Subclass of ConstIterator that only overrides operator* to return raw spans.
    class ConstRawIterator : public ConstIterator {
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = tcb::span<const uint8_t>;
        using difference_type = std::ptrdiff_t;
        using pointer = void;
        using reference = value_type;

        using ConstIterator::ConstIterator;
        tcb::span<const uint8_t> operator*() const;
    };
    struct RawElementsView {
        const ByteBuffer* buffer;
        ConstRawIterator begin() const { return ConstRawIterator(buffer, buffer->prefix_size_); }
        ConstRawIterator end() const { return ConstRawIterator(buffer, buffer->elements_span_.size()); }
    };
    RawElementsView raw_elements() const;

protected:
    // Helper for reserve heuristics in variable-size parsing.
    static size_t EstimateOffsetsReserveCountFromSample(tcb::span<const uint8_t> bytes);

    // Helper for calculating the offset of an element by position.
    size_t CalculateOffsetOfElement(size_t position) const;

    // ++++ Needed after deprecating std iterators?
    // Helper to validate the preconditions for reading the buffer with an iterator.
    void ValidateIteratorReadPreconditions() const;

    // Helper to get a writable span for an element during SetElement calls.
    tcb::span<uint8_t> GetWritableSpanForElement(size_t position, size_t payload_size);

    // Variables for span elements reading
    tcb::span<const uint8_t> elements_span_;
    size_t elements_span_size_;
    mutable size_t num_elements_;
    Codec codec_;

    // Variables for element span iterator.
    mutable const uint8_t* element_iterator_current_ptr_;
    const uint8_t* element_iterator_end_ptr_;

    // Variables for determining offset of elements.
    size_t prefix_size_ = 0;
    size_t element_size_;                   // for fixed-size elements
    mutable std::vector<size_t> offsets_;   // for variable-size elements

    // Variables for write buffer.
    std::vector<uint8_t> write_buffer_;

    // Variable for sequential variable-size writes.
    // Tracks next expected position for sequential variable-size writes.
    // Value is invalidated to kUnsetSize once order is violated.
    size_t next_expected_write_position_ = 0;

private:
    // Initialization methods and flags for read-only buffer
    void InitializeFromSpan() const;
    void EnsureInitializedFromSpan() const;
    mutable bool is_initialized_from_span_ = false;

    // Initialization methods and flags for write buffer
    void InitializeForWriteBuffer(size_t variable_size_reserved_bytes_hint);
    void RebindSpanToWriteBuffer();
    bool is_write_buffer_enabled_ = false;
    bool is_write_buffer_finalized_ = false;    
};

// Constant to mark a size_t value as unset.
inline constexpr size_t kUnsetSize = std::numeric_limits<size_t>::max();

// Constant for the size of the [u32 size] prefix for variable-size elements.
inline constexpr size_t kSizePrefixBytes = sizeof(uint32_t);

inline size_t ReadSizeAt(tcb::span<const uint8_t> bytes, size_t offset) {
    return static_cast<size_t>(read_u32_le(bytes, offset));
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
      elements_span_size_(elements_span.size()),
      element_iterator_current_ptr_(elements_span.data()),
      element_iterator_end_ptr_(elements_span.data() + elements_span.size()),
      num_elements_(kUnsetSize),
      codec_(std::move(codec)),
      element_size_(0),
      prefix_size_(prefix_size),
      is_write_buffer_enabled_(false),
      is_initialized_from_span_(false) {
    if constexpr (is_fixed_sized) {
        element_size_ = codec_.element_size();
    }
}

// Initializes `num_elements_` and `offsets_` from the span.
// Called in a lazy manner when the buffer is accessed with GetElement or GetNumElements, avoiding unnecessary initialization.
template <class Codec>
inline void ByteBuffer<Codec>::InitializeFromSpan() const {
    if (elements_span_size_ < prefix_size_) {
        throw InvalidInputException("Malformed buffer: prefix_size exceeds span size");
    }

    const size_t readable_size = elements_span_size_ - prefix_size_;

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
    while (cursor < elements_span_size_) {
        if (elements_span_size_ - cursor < kSizePrefixBytes) {
            throw InvalidInputException("Malformed variable-size buffer: truncated length prefix");
        }
        offsets_.push_back(cursor);
        const size_t current_element_size = ReadSizeAt(elements_span_, cursor);
        cursor += kSizePrefixBytes;
        if (elements_span_size_ - cursor < current_element_size) {
            throw InvalidInputException("Malformed variable-size buffer: truncated element payload");
        }
        cursor += current_element_size;
    }
    num_elements_ = offsets_.size();
    is_initialized_from_span_ = true;
}

template <class Codec>
inline void ByteBuffer<Codec>::EnsureInitializedFromSpan() const {
    // If the span is already initialized, skip it.
    if (is_initialized_from_span_) {
        return;
    }
    // If the write buffer is initialized, we don't need to initialize from the span.
    if (is_write_buffer_enabled_) {
        return;
    }
    InitializeFromSpan();
}

// For read-only buffers, gets the number of elements in the buffer and sets num_elements_ if not already set.
// A lighter version to only get num_elements_ and avoid calling InitializeFromSpan that also builds offsets_.
template <class Codec>
inline size_t ByteBuffer<Codec>::GetNumElements() const {
    if (num_elements_ != kUnsetSize) {
        return num_elements_;
    }

    // If the buffer is not initialized, initialize it from the span.
    EnsureInitializedFromSpan();
    return num_elements_;
}

template <class Codec>
inline size_t ByteBuffer<Codec>::EstimateOffsetsReserveCountFromSample(tcb::span<const uint8_t> bytes) {
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
inline size_t ByteBuffer<Codec>::CalculateOffsetOfElement(size_t position) const {
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
inline tcb::span<const uint8_t> ByteBuffer<Codec>::GetRawElement(size_t position) const {
    EnsureInitializedFromSpan();
    
    // For fixed-size elements are stored contiguously.
    if constexpr (is_fixed_sized) {
        if (position >= num_elements_) {
            throw InvalidInputException("Element position out of range during GetRawElement");
        }
        const size_t offset = prefix_size_ + (position * element_size_);
        return elements_span_.subspan(offset, element_size_);
    }

    // For variable-size elements, we need to read the size first [u32 size][element].
    if (position >= num_elements_) {
        throw InvalidInputException("Element position out of range during GetRawElement");
    }
    const size_t offset = offsets_[position];
    if (offset == kUnsetSize) {
        throw InvalidInputException("Element position has not been written yet");
    }
    const size_t element_size = ReadSizeAt(elements_span_, offset);
    return elements_span_.subspan(offset + kSizePrefixBytes, element_size);
}

template <class Codec>
inline typename ByteBuffer<Codec>::value_type ByteBuffer<Codec>::GetElement(size_t position) const {
    return codec_.Decode(GetRawElement(position));
}









// -----------------------------------------------------------------------------
// Element span iterator  --  The streamlined version of the iterator.
// -----------------------------------------------------------------------------

// ++++++ Additional validation that this is only used for read-only buffers.
template <class Codec>
inline tcb::span<const uint8_t> ByteBuffer<Codec>::ElementsIteratorNext() const {
    if (element_iterator_current_ptr_ == element_iterator_end_ptr_) {
        return {};
    }

    const size_t bytes_remaining =
        static_cast<size_t>(element_iterator_end_ptr_ - element_iterator_current_ptr_);

    if constexpr (is_fixed_sized) {
        if (bytes_remaining < element_size_) {
            throw InvalidInputException("Malformed fixed-size buffer: truncated element in iterator");
        }
        const auto out_bytes =
            tcb::span<const uint8_t>(element_iterator_current_ptr_, element_size_);
        element_iterator_current_ptr_ += element_size_;
        return out_bytes;
    }

    // Variable-sized elements
    if (bytes_remaining < kSizePrefixBytes) {
        throw InvalidInputException("Malformed variable-size buffer: truncated length prefix in iterator");
    }
    const size_t current_element_size = read_u32_le(element_iterator_current_ptr_);
    element_iterator_current_ptr_ += kSizePrefixBytes;

    const size_t payload_remaining =
        static_cast<size_t>(element_iterator_end_ptr_ - element_iterator_current_ptr_);
    if (payload_remaining < current_element_size) {
        throw InvalidInputException("Malformed variable-size buffer: truncated element payload in iterator");
    }

    const auto out_bytes =
        tcb::span<const uint8_t>(element_iterator_current_ptr_, current_element_size);
    element_iterator_current_ptr_ += current_element_size;
    return out_bytes;
}











// -----------------------------------------------------------------------------
// Element span iterator
//
// Allows an alternative read of elements_span_ without need for lazy initialization of offsets_,
// so saving execution time when the traversal of the buffer is strictly sequential.
// This is the most common behavior when reading elements in single threaded mode.
// -----------------------------------------------------------------------------

template <class Codec>
inline ByteBuffer<Codec>::ConstIterator::ConstIterator(const ByteBuffer<Codec>* buffer, size_t cursor_offset)
    : buffer_(buffer),
      cursor_offset_(cursor_offset),
      elements_span_size_(buffer != nullptr ? buffer->elements_span_size_ : 0u),
      current_element_size_(kUnsetSize) {}

template <class Codec>
inline size_t ByteBuffer<Codec>::ConstIterator::ReadAndValidateVariableElementSizeAtCursor() const {
    // Fixed-sized buffers should not call this method.
    if constexpr (is_fixed_sized) {
        throw InvalidInputException("ReadAndValidateVariableElementSizeAtCursor is not valid for fixed-size codecs");
    }

    // If the current element size has already been read, return it.
    if (current_element_size_ != kUnsetSize) {
        return current_element_size_;
    }

    // Read the current element size and save it to current_element_size_ cached variable.
    if ((elements_span_size_ - cursor_offset_) < kSizePrefixBytes) {
        throw InvalidInputException("Malformed variable-size buffer: truncated length prefix");
    }
    const size_t current_element_size = ReadSizeAt(buffer_->elements_span_, cursor_offset_);
    const size_t payload_offset = cursor_offset_ + kSizePrefixBytes;
    if ((elements_span_size_ - payload_offset) < current_element_size) {
        throw InvalidInputException("Malformed variable-size buffer: truncated element payload");
    }
    current_element_size_ = current_element_size;
    return current_element_size_;
}

template <class Codec>
inline tcb::span<const uint8_t> ByteBuffer<Codec>::ConstIterator::RawSpanAtCursor() const {
    if (buffer_ == nullptr || cursor_offset_ >= elements_span_size_) {
        throw InvalidInputException("Cannot dereference ByteBuffer iterator at end position");
    }
    if constexpr (is_fixed_sized) {
        return buffer_->elements_span_.subspan(cursor_offset_, buffer_->element_size_);
    }
    const size_t current_element_size = ReadAndValidateVariableElementSizeAtCursor();
    const size_t payload_offset = cursor_offset_ + kSizePrefixBytes;
    return buffer_->elements_span_.subspan(payload_offset, current_element_size);
}

template <class Codec>
inline typename ByteBuffer<Codec>::ConstIterator::value_type ByteBuffer<Codec>::ConstIterator::operator*() const {
    // Decode converts raw bytes into the codec's value_type (e.g. int32_t, float, string_view).
    // This keeps the iterator's return type consistent with GetElement across all codecs.
    return buffer_->codec_.Decode(RawSpanAtCursor());
}

template <class Codec>
inline typename ByteBuffer<Codec>::ConstIterator& ByteBuffer<Codec>::ConstIterator::operator++() {
    if (buffer_ == nullptr || cursor_offset_ >= elements_span_size_) {
        return *this;
    }
    if constexpr (is_fixed_sized) {
        cursor_offset_ += buffer_->element_size_;
        return *this;
    }
    const size_t current_element_size = ReadAndValidateVariableElementSizeAtCursor();
    cursor_offset_ += (kSizePrefixBytes + current_element_size);
    current_element_size_ = kUnsetSize;
    return *this;
}

template <class Codec>
inline bool ByteBuffer<Codec>::ConstIterator::operator==(const ConstIterator& other) const {
    return buffer_ == other.buffer_ && cursor_offset_ == other.cursor_offset_;
}

template <class Codec>
inline bool ByteBuffer<Codec>::ConstIterator::operator!=(const ConstIterator& other) const {
    return !(*this == other);
}

template <class Codec>
inline tcb::span<const uint8_t> ByteBuffer<Codec>::ConstRawIterator::operator*() const {
    // Returns the raw bytes for the current element, consistent with GetRawElement.
    return this->RawSpanAtCursor();
}

template <class Codec>
inline void ByteBuffer<Codec>::ValidateIteratorReadPreconditions() const {
    if (is_write_buffer_enabled_) {
        throw InvalidInputException("Iterator is only available for read buffers");
    }
    if (elements_span_size_ < prefix_size_) {
        throw InvalidInputException("Malformed buffer: prefix_size exceeds span size");
    }
    if constexpr (is_fixed_sized) {
        if (element_size_ <= 0) {
            throw InvalidInputException("Invalid fixed-size buffer: element_size must be greater than zero");
        }
        const size_t readable_size = elements_span_size_ - prefix_size_;
        if ((readable_size % element_size_) != 0) {
            throw InvalidInputException("Malformed fixed-size buffer: buffer does not align with element_size");
        }
    }
}

template <class Codec>
inline typename ByteBuffer<Codec>::ConstIterator ByteBuffer<Codec>::begin() const {
    ValidateIteratorReadPreconditions();
    return ConstIterator(this, prefix_size_);
}

template <class Codec>
inline typename ByteBuffer<Codec>::ConstIterator ByteBuffer<Codec>::end() const {
    ValidateIteratorReadPreconditions();
    return ConstIterator(this, elements_span_size_);
}

template <class Codec>
inline typename ByteBuffer<Codec>::RawElementsView ByteBuffer<Codec>::raw_elements() const {
    ValidateIteratorReadPreconditions();
    return RawElementsView{this};
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
      is_write_buffer_enabled_(true),
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
      is_write_buffer_enabled_(true),
      prefix_size_(prefix_size) {
    static_assert(!is_fixed_sized, "ByteBuffer constructor for variable-size elements only.");
    InitializeForWriteBuffer(use_reserve_hint ? reserved_bytes_hint : 0);
}

// Initializes `write_buffer_`, `offsets_` and `elements_span_`
template <class Codec>
inline void ByteBuffer<Codec>::InitializeForWriteBuffer(size_t variable_size_reserved_bytes_hint) {
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

    // offsets_ is initialized so the vector is fully allocated and have random-ish access during writes.
    offsets_.clear();
    offsets_.resize(num_elements_, kUnsetSize);

    // next_expected_sequential_position_ is initialized to 0 for sequential write checking.
    next_expected_write_position_ = 0;

    // elements_span_ is re-bound to the write buffer.
    RebindSpanToWriteBuffer();
}

// -----------------------------------------------------------------------------
// Buffer writer methods
// -----------------------------------------------------------------------------


template <class Codec>
inline tcb::span<uint8_t> ByteBuffer<Codec>::GetWritableSpanForElement(size_t position, size_t payload_size) {
    if (!is_write_buffer_enabled_) {
        throw InvalidInputException("Cannot GetWriteSpanForElement: write buffer is not initialized.");
    }

    if (is_write_buffer_finalized_) {
        throw InvalidInputException("Cannot GetWriteSpanForElement: write buffer has been finalized");
    }

    if (position >= num_elements_) {
        throw InvalidInputException("Element position out of range during GetWriteSpanForElement");
    }

    // For fixed-size elements, we write directly at the fixed offset. No need to re-bind the span.
    if constexpr (is_fixed_sized) {
        if (payload_size != element_size_) {
            throw InvalidInputException("GetWriteSpanForElement: payload does not match element_size");
        }
        const size_t offset = prefix_size_ + (position * element_size_);
        auto write_span = tcb::span<uint8_t>(write_buffer_.data() + offset, element_size_);
        return write_span;
    }
    
    // Variable-sized elements - `else` is needed because it's a compile-time check.
    else {
        // Defensive check for unlikely extremely large element size that exceeds uint32.
        if (payload_size > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) [[unlikely]] {
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
        write_buffer_.resize(offset + kSizePrefixBytes + payload_size);
        auto offset_ptr = write_buffer_.data() + offset;

        // Write the size prefix
        write_u32_le(offset_ptr, static_cast<uint32_t>(payload_size));

        // Update next_expected_write_position_ for sequential write checking.
        if (next_expected_write_position_ != kUnsetSize) {
            if (position == next_expected_write_position_) {
                next_expected_write_position_ += 1;
            } else {
                next_expected_write_position_ = kUnsetSize;
            }
        }

        RebindSpanToWriteBuffer();
        offsets_[position] = offset;
        return tcb::span<uint8_t>(offset_ptr + kSizePrefixBytes, payload_size);;
    }
}

template <class Codec>
inline tcb::span<uint8_t> ByteBuffer<Codec>::GetWritableRawElement(size_t position, size_t payload_size) {
    return GetWritableSpanForElement(position, payload_size);
}

template <class Codec>
inline void ByteBuffer<Codec>::SetElement(size_t position, const value_type& element) {
    if constexpr (is_fixed_sized) {
        auto write_span = GetWritableSpanForElement(position, element_size_);
        codec_.Encode(element, write_span);
    } else {
        auto write_span = GetWritableSpanForElement(position, static_cast<size_t>(element.size()));
        codec_.Encode(element, write_span);
    }
}

template <class Codec>
inline void ByteBuffer<Codec>::SetRawElement(size_t position, tcb::span<const uint8_t> raw) {
    auto write_span = GetWritableSpanForElement(position, raw.size());
    std::memcpy(write_span.data(), raw.data(), raw.size());
}

template <class Codec>
inline std::vector<uint8_t> ByteBuffer<Codec>::FinalizeAndTakeBuffer() {
    if (is_write_buffer_finalized_) {
        throw InvalidInputException("FinalizeAndTakeBuffer: write buffer has already been finalized");
    }

    if (!is_write_buffer_enabled_) {
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
        if (element_offset == kUnsetSize) {
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
    is_write_buffer_enabled_ = false;
    is_write_buffer_finalized_ = true;
    
    return result;
}

template <class Codec>
inline void ByteBuffer<Codec>::RebindSpanToWriteBuffer() {
    auto write_buffer_size = write_buffer_.size();
    elements_span_ = tcb::span<const uint8_t>(write_buffer_.data(), write_buffer_size);
    elements_span_size_ = write_buffer_size;
}

} // namespace dbps::processing
