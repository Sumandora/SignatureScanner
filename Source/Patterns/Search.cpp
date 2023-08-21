#include "SignatureScanner.hpp"

std::size_t SignatureScanner::PatternSignature::length() const
{
	return elements.size();
}

bool SignatureScanner::PatternSignature::doesMatch(const char* addr) const
{
	for (size_t i = 0; i < elements.size(); i++) {
		auto byte = elements[i];
		if (byte.has_value() && *(addr + i) != byte.value())
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
// However when searching we expect that reading outside of begin/end
// may lead to sigsegv or similiar faults, because we read non-readable memory regions.
// In case you are reading this and wan't this behaviour, simply add/subtract the Length()
// from the boundary that you want to extend

const char* SignatureScanner::PatternSignature::prev(const char* addr, const char* end) const
{
	addr -= length();

	while (!end || addr >= end) {
		if (doesMatch(addr))
			return addr;
		addr--;
	}

	return nullptr;
}

const char* SignatureScanner::PatternSignature::next(const char* addr, const char* end) const
{
	if (end)
		end -= length();

	while (!end || addr <= end) {
		if (doesMatch(addr))
			return addr;
		addr++;
	}

	return nullptr;
}

std::vector<const char*> SignatureScanner::PatternSignature::all(const char* addr, const char* end) const
{
	if (end)
		end -= length();

	std::vector<const char*> hits;
	while (!end || addr <= end) {
		if (doesMatch(addr))
			hits.push_back(addr);
		addr++;
	}

	return hits;
}