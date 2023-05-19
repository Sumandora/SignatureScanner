#ifndef IDASIGNATURESCANNER
#define IDASIGNATURESCANNER

#include <span>
#include <string>
#include <vector>

using Byte = std::pair<unsigned char, bool>;
using Signature = std::vector<Byte>;

namespace SignatureScanner {
	Signature BuildSignature(const std::string& str);
	bool DoesMatch(const Signature& signature, void* address);

	void* FindNextOccurrence(const Signature& signature, void* begin, void* end = nullptr);
	inline void* FindNextOccurrence(const Signature& signature, std::span<std::byte> span) { return FindNextOccurrence(signature, &span.front(), &span.back()); }

	std::vector<void*> FindAllOccurrences(const Signature& signature, void* begin, void* end);
	inline std::vector<void*> FindAllOccurrences(const Signature& signature, std::span<std::byte> span) { return FindAllOccurrences(signature, &span.front(), &span.back()); }
}

#endif
