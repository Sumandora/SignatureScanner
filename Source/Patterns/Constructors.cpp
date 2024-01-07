#include "SignatureScanner.hpp"

#include <algorithm>
#include <sstream>

SignatureScanner::PatternSignature::PatternSignature(std::vector<PatternSignature::Element> elements)
	: elements(std::move(elements))
{
}

SignatureScanner::StringSignature::StringSignature(const std::string& string, std::optional<char> wildcard)
	: PatternSignature({})
{
	for (char c : string) {
		if(wildcard == c)
			elements.emplace_back(std::nullopt);
		else
			elements.emplace_back(static_cast<std::byte>(c));
	}
}

SignatureScanner::ByteSignature::ByteSignature(const std::string& string, const char wildcard)
	: PatternSignature({})
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

SignatureScanner::ByteSignature::ByteSignature(const char* bytes, const std::string& mask, char maskChar)
	: PatternSignature({})
{
	for(std::size_t i = 0; i < mask.length(); i++) {
		if(mask[i] == maskChar)
			elements.emplace_back(static_cast<std::byte>(bytes[i]));
		else
			elements.emplace_back(std::nullopt);
	}
}
