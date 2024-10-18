#ifndef SIGNATURESCANNER_DETAIL_SIGNATURECONCEPT_HPP
#define SIGNATURESCANNER_DETAIL_SIGNATURECONCEPT_HPP

#include <concepts>
#include <cstddef>
#include <iterator>
#include <span>
#include <vector>

namespace SignatureScanner::detail {
	using ByteSpanIterator = std::span<std::byte>::iterator;
	template <typename T>
	concept Signature = requires(T signature, ByteSpanIterator iterator, ByteSpanIterator end, std::back_insert_iterator<std::vector<ByteSpanIterator>> inserter) {
		{ signature.next(iterator, end) } -> std::same_as<ByteSpanIterator>;
		{ signature.prev(iterator, end) } -> std::same_as<ByteSpanIterator>;
		{ signature.all(iterator, end, inserter) };

		{ signature.doesMatch(iterator, end) } -> std::convertible_to<bool>;
	};
}

#endif
