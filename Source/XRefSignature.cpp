#include "SignatureScanner/XRefSignature.hpp"

#include <cstddef>
#include <cstdint>

// This is the same code, but since this translation unit is optimized these will both run faster as they will be inlined heavily.
// To prevent the compiler from cheating and just calling a common does_match, the flatten attribute is used.

#include "Flatten.hpp"

FLATTEN const std::byte* SignatureScanner::XRefSignature::optimized_next(const std::byte* it, const std::byte* end, std::uintptr_t location) const
{
	for (; it != end; it++)
		if (does_match(it, end, location++))
			return it;
	return it;
}

FLATTEN const std::byte* SignatureScanner::XRefSignature::optimized_prev(const std::byte* it, const std::byte* end, std::uintptr_t location) const
{
	for (; it != end; it--)
		if (does_match(it, end, location--))
			return it;
	return it;
}
