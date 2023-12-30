#ifndef SIGNATURESCANNER_HPP
#define SIGNATURESCANNER_HPP

#include <optional>
#include <string>
#include <vector>
#include <cstdint>

namespace SignatureScanner {

	class Signature {
		[[nodiscard]] virtual std::optional<std::uintptr_t> prev(std::uintptr_t begin, std::optional<std::uintptr_t> end) const = 0;
		[[nodiscard]] virtual std::optional<std::uintptr_t> next(std::uintptr_t begin, std::optional<std::uintptr_t> end) const = 0;
		[[nodiscard]] virtual std::vector<std::uintptr_t> all(std::uintptr_t begin, std::uintptr_t end) const = 0;

	public:
		virtual ~Signature() = default;

		template <typename R = std::uintptr_t, typename T, typename T2 = std::uintptr_t>
		[[nodiscard]] inline std::optional<R> findPrev(T begin, std::optional<T2> end = std::nullopt) const
		{
			auto res = prev(std::uintptr_t(begin), end.has_value() ? std::optional{std::uintptr_t(end.value())} : std::nullopt);
			if(res.has_value())
				return R(res.value());
			return std::nullopt;
		}

		template <typename R = std::uintptr_t, typename T, typename T2 = std::uintptr_t>
		[[nodiscard]] inline std::optional<R> findNext(T begin, std::optional<T2> end = std::nullopt) const
		{
			auto res = next(std::uintptr_t(begin), end.has_value() ? std::optional{std::uintptr_t(end.value())} : std::nullopt);
			if(res.has_value())
				return R(res.value());
			return std::nullopt;
		}

		template <typename R = std::uintptr_t, typename T, typename T2 = std::uintptr_t>
		[[nodiscard]] inline std::vector<R> findAll(T begin, T2 end) const
		{
			std::vector<std::uintptr_t> vector = all(std::uintptr_t(begin), std::uintptr_t(end));
			if constexpr (std::is_convertible_v<std::vector<std::uintptr_t>, std::vector<R>>)
				return vector;
			else { // when you are using this path then you are enduring a performance hit because the vector has to be copied first
				std::vector<R> newVector{};
				for (std::uintptr_t v : vector) {
					newVector.push_back(R(v));
				}
				return newVector;
			}
		}
	};

	class PatternSignature : public Signature {
	private:
		[[nodiscard]] std::optional<std::uintptr_t> prev(std::uintptr_t begin, std::optional<std::uintptr_t> end) const override;
		[[nodiscard]] std::optional<std::uintptr_t> next(std::uintptr_t begin, std::optional<std::uintptr_t> end) const override;
		[[nodiscard]] std::vector<std::uintptr_t> all(std::uintptr_t begin, std::uintptr_t end) const override;

	public:
		using Element = std::optional<std::byte>;

	protected:
		std::vector<Element> elements;

	public:
		explicit PatternSignature(std::vector<PatternSignature::Element> elements);

		[[nodiscard]] std::size_t length() const;

		[[nodiscard]] bool doesMatch(std::uintptr_t addr) const;

		template <typename T = std::uintptr_t>
		[[nodiscard]] bool doesMatch(T addr) const
		{
			return doesMatch(std::uintptr_t(addr));
		}
	};

	class StringSignature : public PatternSignature {
	public:
		explicit StringSignature(const std::string& string, std::optional<char> wildcard = std::nullopt);
	};

	class ByteSignature : public PatternSignature {
	public:
		explicit ByteSignature(const std::string& bytes, char wildcard = '?');
		explicit ByteSignature(const char* bytes, char wildcard = '?');

		ByteSignature(const char* bytes, std::string mask, char maskChar = 'x' /*defines the char which enables a byte, not the one which disables one*/);
	};

	class XRefSignature : public Signature {
		const std::uintptr_t address;
		const bool relativeReferences;
		const bool absoluteReferences;

		[[nodiscard]] std::optional<std::uintptr_t> prev(std::uintptr_t begin, std::optional<std::uintptr_t> end) const override;
		[[nodiscard]] std::optional<std::uintptr_t> next(std::uintptr_t begin, std::optional<std::uintptr_t> end) const override;
		[[nodiscard]] std::vector<std::uintptr_t> all(std::uintptr_t begin, std::uintptr_t end) const override;

	public:
		explicit XRefSignature(std::uintptr_t address, bool relativeReferences = true, bool absoluteReferences = true);
		explicit XRefSignature(const void* address, bool relativeReferences = true, bool absoluteReferences = true);

		[[nodiscard]] bool doesMatch(std::uintptr_t addr, std::size_t space) const;

		template <typename T = std::uintptr_t>
		[[nodiscard]] bool doesMatch(T addr, std::size_t space /* relative (2 or 4) and absolute (4 or 8) references have different lengths */) const
		{
			return doesMatch(std::uintptr_t(addr), space);
		}
	};
}

#endif
