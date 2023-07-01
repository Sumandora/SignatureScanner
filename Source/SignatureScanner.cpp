#include "SignatureScanner.hpp"

SignatureScanner::Signature::Signature()
{
	elements = {};
}

SignatureScanner::Signature::Signature(std::vector<Element> elements)
{
	this->elements = elements;
}

bool SignatureScanner::Signature::DoesMatch(const char* addr) const
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

const char* SignatureScanner::Signature::Prev(const char* addr, const char* end) const
{
	addr -= Length();

	while (!end || addr >= end) {
		if (DoesMatch(addr))
			return addr;
		addr--;
	}

	return nullptr;
}

const char* SignatureScanner::Signature::Next(const char* addr, const char* end) const
{
	if (end)
		end -= Length();

	while (!end || addr <= end) {
		if (DoesMatch(addr))
			return addr;
		addr++;
	}

	return nullptr;
}

std::vector<const char*> SignatureScanner::Signature::All(const char* addr, const char* end) const
{
	if (end)
		end -= Length();

	std::vector<const char*> hits;
	while (!end || addr <= end) {
		if (DoesMatch(addr))
			hits.push_back(addr);
		addr++;
	}

	return hits;
}