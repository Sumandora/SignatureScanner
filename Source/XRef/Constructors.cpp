#include "SignatureScanner.hpp"

SignatureScanner::XRefSignature::XRefSignature(const void* address, const bool relativeReferences, const bool absoluteReferences)
	: address(reinterpret_cast<const char*>(address))
	, relativeReferences(relativeReferences)
	, absoluteReferences(absoluteReferences)
{
}