#include "SignatureScanner/XRefSignature.hpp"

#include <cstddef>
#include <cstdint>

// This is the same code, but since this translation unit is optimized these will both run faster as they will be inlined heavily.
// To prevent the compiler from cheating and just calling a common does_match, the flatten attribute is used.

#include "Flatten.hpp"

namespace SignatureScanner {
	// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DEFINE_OPTIMIZED_CLASS(class_name)                                        \
	template <>                                                                   \
	FLATTEN const std::byte* class_name::optimized_next(                          \
		const std::byte* it, const std::byte* end, std::uintptr_t location) const \
	{                                                                             \
		return unoptimized_next(it, end, location);                               \
	}                                                                             \
                                                                                  \
	template <>                                                                   \
	FLATTEN const std::byte* class_name::optimized_prev(                          \
		const std::byte* it, const std::byte* end, std::uintptr_t location) const \
	{                                                                             \
		return unoptimized_prev(it, end, location);                               \
	}

	DEFINE_OPTIMIZED_CLASS(XRefSignature<XRefTypes::RELATIVE>)
	DEFINE_OPTIMIZED_CLASS(XRefSignature<XRefTypes::ABSOLUTE>)
	DEFINE_OPTIMIZED_CLASS(XRefSignature<XRefTypes::RELATIVE_AND_ABSOLUTE>)
}
