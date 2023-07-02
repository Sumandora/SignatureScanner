#include "SignatureScanner.hpp"

#include <sstream>

#ifdef SIGNATURESCANNER_ENABLE_STRING_SEARCH
SignatureScanner::StringSignature::StringSignature(const std::string& string)
	: PatternSignature()
{
	for (char c : string) {
		elements.push_back(static_cast<char>(c));
	}
}
#endif

#ifdef SIGNATURESCANNER_ENABLE_IDA_SEARCH
SignatureScanner::ByteSignature::ByteSignature(const std::string& string)
	: PatternSignature()
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
#endif
