#ifndef SIGNATURESCANNER_HPP
#define SIGNATURESCANNER_HPP

#include <optional>
#include <string>
#include <vector>

namespace SignatureScanner {
	using Element = std::optional<char>;

	class Signature {
	protected:
		std::vector<Element> elements;

	public:
		Signature();
		Signature(std::vector<Element>);

		inline std::size_t Length() const
		{
			return elements.size();
		}

		bool DoesMatch(const char* addr) const;

		template <typename T>
		bool DoesMatch(std::add_const_t<T> addr) const
		{
			return DoesMatch(reinterpret_cast<const char*>(addr));
		}

		const char* Prev(const char* begin, const char* end) const;
		const char* Next(const char* begin, const char* end) const;
		std::vector<const char*> All(const char* begin, const char* end) const;

		template <typename R, typename T, typename T2 = void*>
		inline R Prev(T begin, T2 end = nullptr) const
		{
			const char* ptr = Prev(reinterpret_cast<const char*>(begin), reinterpret_cast<const char*>(end));
			if constexpr (!std::is_const_v<std::remove_pointer_t<R>>)
				return reinterpret_cast<R>(const_cast<char*>(ptr)); // This isn't good, but it removes lots of duplicated code
			else
				return reinterpret_cast<R>(ptr);
		}

		template <typename R, typename T, typename T2 = void*>
		inline R Next(T begin, T2 end = nullptr) const
		{
			const char* ptr = Next(reinterpret_cast<const char*>(begin), reinterpret_cast<const char*>(end));
			if constexpr (!std::is_const_v<std::remove_pointer_t<R>>)
				return reinterpret_cast<R>(const_cast<char*>(ptr)); // This isn't good, but it removes lots of duplicated code
			else
				return reinterpret_cast<R>(ptr);
		}

		template <typename R, typename T, typename T2 = void*>
		inline std::vector<R> All(T begin, T2 end = nullptr) const
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

	class StringSignature : public Signature {
	public:
		StringSignature() = delete;
		StringSignature(const std::string& string);
	};

	class ByteSignature : public Signature {
	public:
		ByteSignature() = delete;
		ByteSignature(const std::string& bytes);
	};
}

#endif
