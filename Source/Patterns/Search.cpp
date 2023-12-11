#include "SignatureScanner.hpp"

std::size_t SignatureScanner::PatternSignature::length() const
{
	return elements.size();
}

bool SignatureScanner::PatternSignature::doesMatch(std::uintptr_t addr) const
{
	for (size_t i = 0; i < elements.size(); i++) {
		auto byte = elements[i];
		if (byte.has_value() && *reinterpret_cast<std::byte*>(addr + i) != byte.value())
			return false;
	}

	return true;
}

// These '-= Length()' subtractions might be weird for some users
//
// A search after ABCDEF with '|' being begin/end
// -------AAAAAAAAAAAAAAAABCDEF---------
//        |              |
// Should still be a hit here, because the first byte is inside the boundaries.
// However, when searching we expect that reading outside begin/end
// may lead to sigsegv or similiar faults, because we read non-readable memory regions.
// In case you are reading this and want this behaviour, simply add/subtract the Length()
// from the boundary that you want to extend

std::optional<std::uintptr_t> SignatureScanner::PatternSignature::prev(std::uintptr_t addr, std::optional<std::uintptr_t> end) const
{
	addr -= length();

	while (!end.has_value() || addr >= end.value()) {
		if (doesMatch(addr))
			return addr;
		addr--;
	}

	return std::nullopt;
}

std::optional<std::uintptr_t> SignatureScanner::PatternSignature::next(std::uintptr_t addr, std::optional<std::uintptr_t> end) const
{
	if (end.has_value())
		end.value() -= length();

	while (!end.has_value() || addr <= end.value()) {
		if (doesMatch(addr))
			return addr;
		addr++;
	}

	return std::nullopt;
}

std::vector<std::uintptr_t> SignatureScanner::PatternSignature::all(std::uintptr_t addr, std::uintptr_t end) const
{
	if (end)
		end -= length();

	std::vector<std::uintptr_t> hits;
	while (!end || addr <= end) {
		if (doesMatch(addr))
			hits.push_back(addr);
		addr++;
	}

	return hits;
}