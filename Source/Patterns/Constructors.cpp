#include "SignatureScanner.hpp"

#include <sstream>
#include <algorithm>

SignatureScanner::StringSignature::StringSignature(const std::string& string)
	: PatternSignature()
{
	for (char c : string) {
		elements.emplace_back(static_cast<char>(c));
	}
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
			elements.emplace_back(static_cast<char>(strtol(word.c_str(), nullptr, 16)));
	}
}