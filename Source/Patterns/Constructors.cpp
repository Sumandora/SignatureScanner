#include "SignatureScanner.hpp"

#include <algorithm>
#include <sstream>

SignatureScanner::StringSignature::StringSignature(const std::string& string)
	: PatternSignature()
{
	for (char c : string) {
		elements.emplace_back(static_cast<std::byte>(c));
	}
}

SignatureScanner::StringSignature::StringSignature(const char* string)
	: StringSignature(std::string{ string })
{
}

SignatureScanner::ByteSignature::ByteSignature(const std::string& string, const char wildcard)
	: PatternSignature()
{
	std::stringstream iss{ string };
	std::string word;
	while (std::getline(iss, word, ' ')) {
		if (std::all_of(word.begin(), word.end(), [wildcard](char c) { return c == wildcard; }))
			elements.emplace_back(std::nullopt);
		else
			elements.emplace_back(static_cast<std::byte>(strtol(word.c_str(), nullptr, 16)));
	}
}

SignatureScanner::ByteSignature::ByteSignature(const char* bytes, char wildcard)
	: ByteSignature(std::string{ bytes }, wildcard)
{
}