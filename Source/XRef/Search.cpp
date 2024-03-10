#include "SignatureScanner.hpp"

#include <limits>

using RelAddrType = std::conditional_t<sizeof(void*) == 8, std::int32_t, std::int16_t>;

bool SignatureScanner::XRefSignature::doesMatch(std::uintptr_t addr, const std::size_t space) const
{
	// When addressing in native amount of bits there is no reason for a relative address
	if (absoluteReferences && space > sizeof(char*) && *reinterpret_cast<std::uintptr_t*>(addr) == address) {
		return true;
	}

	if (relativeReferences && std::max(address, addr) - std::min(address, addr) < std::numeric_limits<RelAddrType>::max() && space > sizeof(RelAddrType)) {
		if (addr + sizeof(RelAddrType) + *reinterpret_cast<RelAddrType*>(addr) == address) {
			return true;
		}
	}

	return false;
}

std::optional<std::uintptr_t> SignatureScanner::XRefSignature::prev(std::uintptr_t addr, std::optional<std::uintptr_t> end) const
{
	std::uintptr_t begin = addr;

	while (!end.has_value() || addr >= end.value()) {
		if (doesMatch(addr, begin - addr))
			return addr;
		addr--;
	}

	return std::nullopt;
}

std::optional<std::uintptr_t> SignatureScanner::XRefSignature::next(std::uintptr_t addr, std::optional<std::uintptr_t> end) const
{
	while (!end.has_value() || addr <= end.value()) {
		if (doesMatch(addr, end.has_value() ? end.value() - addr : std::numeric_limits<std::size_t>::max()))
			return addr;
		addr++;
	}

	return std::nullopt;
}

std::vector<std::uintptr_t> SignatureScanner::XRefSignature::all(std::uintptr_t addr, std::uintptr_t end) const
{
	std::vector<std::uintptr_t> hits;
	while (!end || addr <= end) {
		if (doesMatch(addr, end ? end - addr : std::numeric_limits<std::size_t>::max()))
			hits.push_back(addr);
		addr++;
	}

	return hits;
}