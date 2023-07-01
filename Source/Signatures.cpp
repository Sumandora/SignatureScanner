#include "SignatureScanner.hpp"

#include <sstream>

SignatureScanner::StringSignature::StringSignature(const std::string& string)
	: Signature()
{
	for (char c : string) {
		elements.push_back(static_cast<char>(c));
	}
}

SignatureScanner::ByteSignature::ByteSignature(const std::string& string)
	: Signature()
{
	std::stringstream iss{ string };
	std::string word;
	while (std::getline(iss, word, ' ')) {
		if (word == "?" || word == "??")
			elements.emplace_back(std::nullopt);
		else
			elements.emplace_back(static_cast<char>(strtol(word.c_str(), nullptr, 16)));
	}
}