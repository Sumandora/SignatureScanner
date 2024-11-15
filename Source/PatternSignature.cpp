#include "SignatureScanner/PatternSignature.hpp"
#include "SignatureScanner/detail/PatternParser.hpp"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <memory>

// This is the same code, but since this translation unit is optimized these will both run faster as they will be inlined heavily.

#include "Flatten.hpp"

FLATTEN const std::byte* SignatureScanner::PatternSignature::optimizedNext(const std::byte* begin, const std::byte* end) const
{
	return std::ranges::search(begin, end, elements.cbegin(), elements.cend(), detail::patternCompare<std::byte>).begin();
}

FLATTEN const std::byte* SignatureScanner::PatternSignature::optimizedPrev(const std::byte* begin, const std::byte* end) const
{
	auto rbegin = std::make_reverse_iterator(begin);
	auto rend = std::make_reverse_iterator(end);
	auto match = std::ranges::search(rbegin, rend, elements.crbegin(), elements.crend(), detail::patternCompare<std::byte>).end();
	return std::to_address(match);
}
