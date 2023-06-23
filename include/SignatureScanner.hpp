#ifndef SIGNATURESCANNER_HPP
#define SIGNATURESCANNER_HPP

#include <span>
#include <string>
#include <vector>

namespace SignatureScanner {
	class Signature {
		std::vector<std::pair<unsigned char, bool>> bytes;

	public:
		Signature() = delete;
		Signature(const std::string& str);

		inline std::size_t Size() const { return bytes.size(); }
		bool DoesMatch(void* address) const;

		void* FindLastOccurrence(void* begin, void* end = nullptr) const;
		inline void* FindLastOccurrence(std::span<std::byte> span) const { return FindLastOccurrence(&span.front(), &span.back()); }

		void* FindNextOccurrence(void* begin, void* end = nullptr) const;
		inline void* FindNextOccurrence(std::span<std::byte> span) const { return FindNextOccurrence(&span.front(), &span.back()); }

		std::vector<void*> FindAllOccurrences(void* begin, void* end) const;
		inline std::vector<void*> FindAllOccurrences(std::span<std::byte> span) const { return FindAllOccurrences(&span.front(), &span.back()); }
	};
}

#endif
