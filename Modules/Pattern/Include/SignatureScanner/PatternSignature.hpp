#ifndef SIGNATURESCANNER_PATTERNSIGNATURE_HPP
#define SIGNATURESCANNER_PATTERNSIGNATURE_HPP

#include "SignatureScanner/SignatureScanner.hpp"

#include <optional>
#include <algorithm>
#include <cstdint>
#include <vector>

namespace SignatureScanner {
	namespace detail {
		using InnerPatternElement = std::byte;
		using PatternElement = std::optional<InnerPatternElement>;

		template <typename T>
		constexpr auto patternCompare(const T& byte, const detail::PatternElement& elem)
		{
			return !elem.has_value() || elem.value() == byte;
		}

		/**
		 * This thing is pretty much useless outside of this use-case,
		 * because the array could be partially filled up when we get it,
		 * for our use-case this doesn't matter.
		 */
		template <typename T, std::size_t N>
		struct ArrayInserter {
			std::array<T, N>& array;
			std::size_t idx = 0;

			constexpr explicit ArrayInserter(std::array<T, N>& array)
				: array(array)
			{
			}

			constexpr ArrayInserter& operator=(T obj)
			{
				array[idx] = obj;
				idx++;
				return *this;
			}

			constexpr ArrayInserter& operator*()
			{
				return *this;
			}
			constexpr ArrayInserter& operator++()
			{
				return *this;
			}
			constexpr ArrayInserter& operator++(int)
			{
				return *this;
			}
		};

		template <std::size_t N>
		struct TemplateString : std::array<char, N> {
#pragma clang diagnostic push
#pragma ide diagnostic ignored "google-explicit-constructor"
			constexpr TemplateString(const char (&str)[N + 1])
				: std::array<char, N>()
			{
				std::copy(std::begin(str), std::end(str) - 1, ArrayInserter(*this));
			}
#pragma clang diagnostic pop
		};

		template <std::size_t N>
		TemplateString(const char (&str)[N]) -> TemplateString<N - 1>;
	}

	namespace IDA {
		namespace ida_detail {
			constexpr uint8_t chrToHex(char c)
			{
				if ('0' <= c && c <= '9') {
					return c - '0';
				} else if ('A' <= c && c <= 'F') {
					return c - 'A' + 10;
				} else if ('a' <= c && c <= 'f') {
					return c - 'a' + 10;
				}
				return 0;
			}

			constexpr uint8_t strToHex(std::string_view input)
			{
				uint8_t val = 0;
				for (char c : input) {
					val *= 16;
					val += chrToHex(c);
				}
				return val;
			}

			template <detail::TemplateString string>
			constexpr std::size_t countWords(char delimiter)
			{
				bool wasChar = false;

				std::size_t count = 0;
				for (char c : string) {
					bool isChar = c != delimiter;
					if (!wasChar && isChar)
						count++;

					wasChar = c != delimiter;
				}

				return count;
			}

			constexpr detail::PatternElement buildWord(std::string_view word, char wildcard)
			{
				if (std::ranges::all_of(word, [wildcard](char c) { return c == wildcard; }))
					return std::nullopt;
				else
					return static_cast<detail::InnerPatternElement>(strToHex(word));
			}

			template <typename Range, typename Inserter>
			constexpr void buildSignature(const Range& range, Inserter inserter, char Delimiter, char Wildcard)
			{
				std::string word;

				std::size_t idx = 0;
				for (char c : range)
					if (c == Delimiter) {
						if (word.empty())
							continue;

						inserter = buildWord(word, Wildcard);
						idx++;

						word = "";
					} else
						word += c;

				if (!word.empty())
					inserter = buildWord(word, Wildcard);
			}
		}

		const char DEFAULT_DELIMITER = ' ';
		const char DEFAULT_WILDCARD = '?';

		template <detail::TemplateString String, char Delimiter = DEFAULT_DELIMITER, char Wildcard = DEFAULT_WILDCARD>
		consteval auto build()
		{
			constexpr std::size_t Length = ida_detail::countWords<String>(Delimiter);

			std::array<detail::PatternElement, Length> signature;

			ida_detail::buildSignature(String, detail::ArrayInserter(signature), Delimiter, Wildcard);

			return signature;
		}

		constexpr auto build(std::string_view string, char delimiter = DEFAULT_DELIMITER, char wildcard = DEFAULT_WILDCARD)
		{
			std::vector<detail::PatternElement> signature;

			ida_detail::buildSignature(string, std::back_inserter(signature), delimiter, wildcard);

			return signature;
		}
	}

	namespace String {
		const char DEFAULT_WILDCARD = '?';

		template <detail::TemplateString String, bool IncludeTerminator = true, char Wildcard = DEFAULT_WILDCARD>
		consteval auto build()
		{
			std::array<detail::PatternElement, IncludeTerminator ? String.size() + 1 : String.size()> signature;

			for (size_t i = 0; i < String.size(); i++)
				if (String[i] == Wildcard)
					signature[i] = std::nullopt;
				else
					signature[i] = static_cast<detail::InnerPatternElement>(String[i]);

			if constexpr (IncludeTerminator)
				signature[signature.size() - 1] = (static_cast<detail::InnerPatternElement>('\0'));

			return signature;
		}

		constexpr auto build(std::string_view string, bool includeTerminator = true, char wildcard = DEFAULT_WILDCARD)
		{
			std::vector<detail::PatternElement> signature;
			signature.reserve(string.size() + (includeTerminator ? 1 : 0));

			for (char c : string)
				if (c == wildcard)
					signature.emplace_back(std::nullopt);
				else
					signature.emplace_back(static_cast<detail::InnerPatternElement>(c));

			if (includeTerminator)
				signature.emplace_back(static_cast<detail::InnerPatternElement>('\0'));

			return signature;
		}
	}

	template <std::size_t N>
	class PatternSignature : public Signature {
	private:
		std::array<detail::PatternElement, N> elements;

	public:
		static constexpr std::size_t Length = N;
		constexpr PatternSignature(std::array<detail::PatternElement, N>&& elements)
			: elements(std::move(elements))
		{
		}

		[[nodiscard]] constexpr const std::array<detail::PatternElement, N>& getElements() const { return elements; }

		template <typename Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr auto next(const Iter& begin, const Sent& end) const
		{
			return std::ranges::search(begin, end, elements.cbegin(), elements.cend(), detail::patternCompare<decltype(*std::declval<Iter>())>).begin();
		}

		template <typename Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr auto prev(const Iter& begin, const Sent& end) const
		{
			return std::ranges::search(begin, end, elements.crbegin(), elements.crend(), detail::patternCompare<decltype(*std::declval<Iter>())>).begin();
		}

		template <typename Iter>
		[[nodiscard]] constexpr bool doesMatch(const Iter& iter) const
		{
			return std::equal(elements.cbegin(), iter.cbegin(), elements.cend(), std::next(iter.cbegin(), elements.length()), detail::patternCompare<decltype(*std::declval<Iter>())>);
		}
	};
}

#endif
