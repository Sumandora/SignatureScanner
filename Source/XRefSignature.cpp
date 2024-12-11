#include "SignatureScanner/XRefSignature.hpp"

#include <cstddef>

// This is the same code, but since this translation unit is optimized these will both run faster as they will be inlined heavily.
// To prevent the compiler from cheating and just calling a common doesMatch, the flatten attribute is used.

#include "Flatten.hpp"

FLATTEN const std::byte* SignatureScanner::XRefSignature::optimizedNext(const std::byte* it, const std::byte* end) const
{
	for (; it != end; it++)
		if (doesMatch(it, end))
			return it;
	return it;
}

FLATTEN const std::byte* SignatureScanner::XRefSignature::optimizedPrev(const std::byte* it, const std::byte* end) const
{
	for (; it != end; it--)
		if (doesMatch(it, end))
			return it;
	return it;
}
