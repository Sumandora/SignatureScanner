#include "IDASignatureScanner.hpp"

#include <algorithm>
#include <ranges>
#include <sstream>

Signature SignatureScanner::BuildSignature(const std::string& str) {
	Signature signature;

	std::istringstream iss(str);
	std::string word;
	while (std::getline(iss, word, ' ')) {
		if(word == "?" || word == "??")
			signature.emplace_back( 0x0, false );
		else
			signature.emplace_back( strtol(word.c_str(), nullptr, 16), true );
	}

	return signature;
}

bool SignatureScanner::DoesMatch(const Signature& signature, void* address) {
	for(size_t i = 0; i < signature.size(); i++) {
		auto byte = signature[i];
		if(byte.second && *(reinterpret_cast<unsigned char*>(address) + i) != byte.first)
			return false;
	}

	return true;
}

void* SignatureScanner::FindNextOccurrence(const Signature& signature, void* begin, void* end) {
	while(true) {
		if(DoesMatch(signature, begin))
			return begin;
		begin = reinterpret_cast<unsigned char*>(begin) + 1;
                if(end && begin > end)
                        return nullptr;
	}
}

std::vector<void*> SignatureScanner::FindAllOccurrences(const Signature& signature, void* begin, void* end) {
	std::vector<void*> hits;

	while(true) {
		if(DoesMatch(signature, begin))
			hits.emplace_back(begin);
		begin = reinterpret_cast<unsigned char*>(begin) + 1;
		if(begin > end)
			return hits;
	}
}
