#ifndef SIGNATURESCANNER_HPP
#define SIGNATURESCANNER_HPP

#include <optional>
#include <string>
#include <vector>

namespace SignatureScanner {

	class Signature {
		[[nodiscard]] virtual const char* prev(const char* begin, const char* end) const = 0;
		[[nodiscard]] virtual const char* next(const char* begin, const char* end) const = 0;
		[[nodiscard]] virtual std::vector<const char*> all(const char* begin, const char* end) const = 0;

	public:
		template <typename R, typename T, typename T2 = void*>
		[[nodiscard]] inline R findPrev(T begin, T2 end = nullptr) const
		{
			const char* ptr = prev(reinterpret_cast<const char*>(begin), reinterpret_cast<const char*>(end));
			if constexpr (!std::is_const_v<std::remove_pointer_t<R>>)
				return reinterpret_cast<R>(const_cast<char*>(ptr)); // This isn't good, but it removes lots of duplicated code
			else
				return reinterpret_cast<R>(ptr);
		}

		template <typename R, typename T, typename T2 = void*>
		[[nodiscard]] inline R findNext(T begin, T2 end = nullptr) const
		{
			const char* ptr = next(reinterpret_cast<const char*>(begin), reinterpret_cast<const char*>(end));
			if constexpr (!std::is_const_v<std::remove_pointer_t<R>>)
				return reinterpret_cast<R>(const_cast<char*>(ptr)); // This isn't good, but it removes lots of duplicated code
			else
				return reinterpret_cast<R>(ptr);
		}

		template <typename R, typename T, typename T2 = void*>
		[[nodiscard]] inline std::vector<R> findAll(T begin, T2 end = nullptr) const
		{
			std::vector<const char*> vector = all(reinterpret_cast<const char*>(begin), reinterpret_cast<const char*>(end));
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

	class PatternSignature : public Signature {
		using Element = std::optional<char>;

	private:
		[[nodiscard]] const char* prev(const char* begin, const char* end) const override;
		[[nodiscard]] const char* next(const char* begin, const char* end) const override;
		[[nodiscard]] std::vector<const char*> all(const char* begin, const char* end) const override;

	protected:
		std::vector<Element> elements;

	public:
		std::size_t length() const;
		[[nodiscard]] bool doesMatch(const char* addr) const;

		template <typename T>
		[[nodiscard]] bool doesMatch(std::add_const_t<T> addr) const
		{
			return doesMatch(reinterpret_cast<const char*>(addr));
		}
	};

	class StringSignature : public PatternSignature {
	public:
		explicit StringSignature(const std::string& string);
	};

	class ByteSignature : public PatternSignature {
	public:
		explicit ByteSignature(const std::string& bytes);
	};

	class XRefSignature : public Signature {
		const char* address;
		const bool relativeReferences;
		const bool absoluteReferences;

		[[nodiscard]] const char* prev(const char* begin, const char* end) const override;
		[[nodiscard]] const char* next(const char* begin, const char* end) const override;
		[[nodiscard]] std::vector<const char*> all(const char* begin, const char* end) const override;

	public:
		explicit XRefSignature(const void* address, bool relativeReferences = true, bool absoluteReferences = true);

		[[nodiscard]] bool doesMatch(const char* addr, std::size_t space /* relative (2 or 4) and absolute (4 or 8) references have different lengths */) const;
	};
}

#endif
