#include "SignatureScanner.hpp"

#include <sstream>

SignatureScanner::Signature::Signature(const std::string& str)
{
	std::istringstream iss(str);
	std::string word;
	while (std::getline(iss, word, ' ')) {
		if (word == "?" || word == "??")
			bytes.emplace_back(0x0, false);
		else
			bytes.emplace_back(strtol(word.c_str(), nullptr, 16), true);
	}
}

bool SignatureScanner::Signature::DoesMatch(void* address)
{
	for (size_t i = 0; i < bytes.size(); i++) {
		auto byte = bytes[i];
		if (byte.second && *(reinterpret_cast<unsigned char*>(address) + i) != byte.first)
			return false;
	}

	return true;
}

void* SignatureScanner::Signature::FindLastOccurrence(void* begin, void* end)
{
	while (true) {
		if (DoesMatch(begin))
			return begin;
		begin = reinterpret_cast<unsigned char*>(begin) - 1;
		if (end && begin < end)
			return nullptr;
	}
}

void* SignatureScanner::Signature::FindNextOccurrence(void* begin, void* end)
{
	while (true) {
		if (DoesMatch(begin))
			return begin;
		begin = reinterpret_cast<unsigned char*>(begin) + 1;
		if (end && begin > end)
			return nullptr;
	}
}

std::vector<void*> SignatureScanner::Signature::FindAllOccurrences(void* begin, void* end)
{
	std::vector<void*> hits;

	while (true) {
		if (DoesMatch(begin))
			hits.emplace_back(begin);
		begin = reinterpret_cast<unsigned char*>(begin) + 1;
		if (begin > end)
			return hits;
	}
}
