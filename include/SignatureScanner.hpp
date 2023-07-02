#ifndef SIGNATURESCANNER_HPP
#define SIGNATURESCANNER_HPP

#include <optional>
#include <string>
#include <vector>

namespace SignatureScanner {

	class Signature {
		virtual const char* Prev(const char* begin, const char* end) const = 0;
		virtual const char* Next(const char* begin, const char* end) const = 0;
		virtual std::vector<const char*> All(const char* begin, const char* end) const = 0;

	public:
		template <typename R, typename T, typename T2 = void*>
		inline R FindPrev(T begin, T2 end = nullptr) const
		{
			const char* ptr = Prev(reinterpret_cast<const char*>(begin), reinterpret_cast<const char*>(end));
			if constexpr (!std::is_const_v<std::remove_pointer_t<R>>)
				return reinterpret_cast<R>(const_cast<char*>(ptr)); // This isn't good, but it removes lots of duplicated code
			else
				return reinterpret_cast<R>(ptr);
		}

		template <typename R, typename T, typename T2 = void*>
		inline R FindNext(T begin, T2 end = nullptr) const
		{
			const char* ptr = Next(reinterpret_cast<const char*>(begin), reinterpret_cast<const char*>(end));
			if constexpr (!std::is_const_v<std::remove_pointer_t<R>>)
				return reinterpret_cast<R>(const_cast<char*>(ptr)); // This isn't good, but it removes lots of duplicated code
			else
				return reinterpret_cast<R>(ptr);
		}

		template <typename R, typename T, typename T2 = void*>
		inline std::vector<R> FindAll(T begin, T2 end = nullptr) const
		{
			std::vector<const char*> vector = All(reinterpret_cast<const char*>(begin), reinterpret_cast<const char*>(end));
			if constexpr (std::is_convertible_v<std::vector<const char*>, std::vector<R>>)
				return vector;
			else {
				std::vector<R> newVector{};
				for (const char* v : vector) {
					if constexpr (!std::is_const_v<std::remove_pointer_t<R>>)
						newVector.push_back(reinterpret_cast<R>(const_cast<char*>(v))); // This isn't good, but it removes lots of duplicated code
					else
						newVector.push_back(reinterpret_cast<R>(v));
				}

				return newVector;
			}
		}
	};

#if defined(SIGNATURESCANNER_ENABLE_IDA_SEARCH) || defined(SIGNATURESCANNER_ENABLE_STRING_SEARCH)
	class PatternSignature : public Signature {
		using Element = std::optional<char>;

	private:
		virtual const char* Prev(const char* begin, const char* end) const override;
		virtual const char* Next(const char* begin, const char* end) const override;
		virtual std::vector<const char*> All(const char* begin, const char* end) const override;

	protected:
		std::vector<Element> elements;

	public:
		std::size_t Length() const;
		bool DoesMatch(const char* addr) const;

		template <typename T>
		bool DoesMatch(std::add_const_t<T> addr) const
		{
			return DoesMatch(reinterpret_cast<const char*>(addr));
		}
	};
#endif

#ifdef SIGNATURESCANNER_ENABLE_STRING_SEARCH
	class StringSignature : public PatternSignature {
	public:
		StringSignature() = delete;
		StringSignature(const std::string& string);
	};
#endif

#ifdef SIGNATURESCANNER_ENABLE_IDA_SEARCH
	class ByteSignature : public PatternSignature {
	public:
		ByteSignature() = delete;
		ByteSignature(const std::string& bytes);
	};
#endif

#ifdef SIGNATURESCANNER_ENABLE_XREF_SEARCH
	class XRefSignature : public Signature {
		const char* address;
		const bool relativeReferences;
		const bool absoluteReferences;

		virtual const char* Prev(const char* begin, const char* end) const override;
		virtual const char* Next(const char* begin, const char* end) const override;
		virtual std::vector<const char*> All(const char* begin, const char* end) const override;

	public:
		XRefSignature(const void* address, const bool relativeReferences = true, const bool absoluteReferences = true);

		bool DoesMatch(const char* addr, const std::size_t space /* relative (2 or 4) and absolute (4 or 8) references have different lengths */) const;
	};
#endif
}

#endif
