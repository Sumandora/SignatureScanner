#ifndef SIGNATURESCANNER_DETAIL_SIGNATURECONCEPT_HPP
#define SIGNATURESCANNER_DETAIL_SIGNATURECONCEPT_HPP

#include <concepts>
#include <cstddef>
#include <iterator>
#include <span>
#include <vector>

namespace SignatureScanner {
	template <typename T, typename I = std::span<std::byte>::iterator>
	concept Signature = requires(T signature, I iterator, I end, std::back_insert_iterator<std::vector<I>> inserter) {
		{ signature.next(iterator, end) } -> std::same_as<I>;
		{ signature.prev(iterator, end) } -> std::same_as<I>;
		{ signature.all(iterator, end, inserter) };

		{ signature.does_match(iterator, end) } -> std::convertible_to<bool>;
	};
}

#endif
