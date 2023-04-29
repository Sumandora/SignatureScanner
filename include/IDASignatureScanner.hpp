#ifndef IDASIGNATURESCANNER
#define IDASIGNATURESCANNER

#include <string>
#include <vector>

typedef std::pair<unsigned char, bool> Byte;
typedef std::vector<Byte> Signature;

namespace SignatureScanner {
	Signature BuildSignature(const std::string& str);
	bool DoesMatch(const Signature& signature, void* address);
        void* FindNextOccurrence(const Signature& signature, void* begin, void* end = nullptr);
	std::vector<void*> FindAllOccurrences(const Signature& signature, void* begin, void* end);
}

#endif
