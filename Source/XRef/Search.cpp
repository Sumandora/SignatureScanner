#include "SignatureScanner.hpp"
#include <cstdint>
#include <limits>

#ifdef SIGNATURESCANNER_ENABLE_XREF_SEARCH

#ifdef SIGNATURESCANNER_FORCE_32BIT_MODE
using RelAddrType = std::int16_t;
#else
using RelAddrType = std::conditional_t<sizeof(void*) == 8, std::int32_t, std::int16_t>;
#endif

bool SignatureScanner::XRefSignature::DoesMatch(const char* addr, const std::size_t space) const
{
	// When addressing in native amount of bits there is no reason for a relative address
	if (absoluteReferences && space > sizeof(char*) && *reinterpret_cast<char* const*>(addr) == address) {
		return true;
	}

	if (relativeReferences && address - addr < std::numeric_limits<RelAddrType>::max() && space > sizeof(RelAddrType)) {
		if (addr + sizeof(RelAddrType) + *reinterpret_cast<const RelAddrType*>(addr) == address) {
			return true;
		}
	}

	return false;
}

const char* SignatureScanner::XRefSignature::Prev(const char* addr, const char* end) const
{
	const char* begin = addr;

	while (!end || addr >= end) {
		if (DoesMatch(addr, begin - addr))
			return addr;
		addr--;
	}

	return nullptr;
}

const char* SignatureScanner::XRefSignature::Next(const char* addr, const char* end) const
{
	while (!end || addr <= end) {
		if (DoesMatch(addr, end - addr))
			return addr;
		addr++;
	}

	return nullptr;
}

std::vector<const char*> SignatureScanner::XRefSignature::All(const char* addr, const char* end) const
{
	std::vector<const char*> hits;
	while (!end || addr <= end) {
		if (DoesMatch(addr, end - addr))
			hits.push_back(addr);
		addr++;
	}

	return hits;
}
#endif