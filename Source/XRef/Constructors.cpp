#include "SignatureScanner.hpp"

SignatureScanner::XRefSignature::XRefSignature(std::uintptr_t address, const bool relativeReferences, const bool absoluteReferences)
	: address(address)
	, relativeReferences(relativeReferences)
	, absoluteReferences(absoluteReferences)
{
}

SignatureScanner::XRefSignature::XRefSignature(const void* address, bool relativeReferences, bool absoluteReferences)
	: XRefSignature(reinterpret_cast<std::uintptr_t>(address), relativeReferences, absoluteReferences)
{
}