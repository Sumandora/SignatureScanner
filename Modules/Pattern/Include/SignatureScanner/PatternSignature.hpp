#ifndef SIGNATURESCANNER_PATTERNSIGNATURE_HPP
#define SIGNATURESCANNER_PATTERNSIGNATURE_HPP

#include "SignatureScanner/SignatureScanner.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace SignatureScanner {
	using InnerPatternElement = std::byte;
	using PatternElement = std::optional<InnerPatternElement>;

	namespace detail {
		template <typename T>
		constexpr auto patternCompare(const T& byte, const PatternElement& elem)
		{
			if (!elem.has_value())
				return true;

			if constexpr (std::equality_comparable_with<T, std::byte>) {
				return elem.value() == byte;
			} else if constexpr (requires() { std::bit_cast<std::byte>(byte); }) {
				return elem.value() == std::bit_cast<std::byte>(byte);
			} else {
				static_assert(false, "T is not a byte(-like) type");
			}
		}

		/**
		 * This thing is pretty much useless outside of this use-case,
		 * because the array could be partially filled up when it is passed here,
		 * for our use-case this doesn't matter.
		 */
		template <typename T, std::size_t N>
		struct ArrayInserter {
			using difference_type = std::ptrdiff_t;

			std::array<T, N>* array;
			std::size_t idx = 0;

			constexpr explicit ArrayInserter(std::array<T, N>& array)
				: array(&array)
			{
			}

			constexpr ArrayInserter& operator=(T obj)
			{
				(*array)[idx] = obj;
				return *this;
			}

			constexpr ArrayInserter& operator*()
			{
				return *this;
			}
			constexpr ArrayInserter& operator++()
			{
				idx++;
				return *this;
			}
			constexpr ArrayInserter operator++(int)
			{
				ArrayInserter it = *this;
				idx++;
				return it;
			}
		};

		template <std::size_t N>
		struct TemplateString : std::array<char, N> {
			// NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
			constexpr TemplateString(const char (&str)[N + 1])
				: std::array<char, N>()
			{
				std::copy(std::begin(str), std::end(str) - 1, ArrayInserter(*this));
			}
		};

		template <std::size_t N>
		TemplateString(const char (&str)[N]) -> TemplateString<N - 1>;

		constexpr uint8_t chrToHex(char c)
		{
			if ('0' <= c && c <= '9') {
				return c - '0';
			}
			if ('A' <= c && c <= 'F') {
				return c - 'A' + 10;
			}
			if ('a' <= c && c <= 'f') {
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

		template <detail::TemplateString String>
		constexpr std::size_t countWords(char delimiter)
		{
			bool wasChar = false;

			std::size_t count = 0;
			for (char c : String) {
				bool isChar = c != delimiter;
				if (!wasChar && isChar)
					count++;

				wasChar = isChar;
			}

			return count;
		}

		constexpr PatternElement buildWord(std::string_view word, char wildcard)
		{
			if (std::ranges::all_of(word, [wildcard](char c) { return c == wildcard; }))
				return std::nullopt;

			return static_cast<InnerPatternElement>(strToHex(word));
		}

		template <std::ranges::input_range Range>
			requires std::convertible_to<std::iter_value_t<std::ranges::iterator_t<Range>>, char>
		constexpr void buildSignature(const Range& range, std::output_iterator<PatternElement> auto inserter, char delimiter, char wildcard)
		{
			std::string word;

			std::size_t idx = 0;
			for (char c : range)
				if (c == delimiter) {
					if (word.empty())
						continue;

					*inserter++ = buildWord(word, wildcard);
					idx++;

					word = "";
				} else
					word += c;

			if (!word.empty())
				*inserter++ = buildWord(word, wildcard);
		}
	}

	class PatternSignature : public Signature {
	private:
		std::vector<PatternElement> elements;

	public:
		// NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
		constexpr PatternSignature(std::vector<PatternElement>&& elements)
			: elements(std::move(elements))
		{
		}

		template <std::size_t N>
		// NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
		constexpr PatternSignature(const std::array<PatternElement, N>& elements)
			: elements(elements.begin(), elements.end())
		{
		}

		[[nodiscard]] constexpr const std::vector<PatternElement>& getElements() const { return elements; }
		[[nodiscard]] constexpr std::size_t getLength() const { return elements.size(); }

		template <std::input_iterator Iter>
		[[nodiscard]] constexpr Iter next(const Iter& begin, const std::sentinel_for<Iter> auto& end) const
		{
			return std::ranges::search(begin, end, elements.cbegin(), elements.cend(), detail::patternCompare<std::iter_value_t<Iter>>).begin();
		}

		template <std::input_iterator Iter>
		[[nodiscard]] constexpr Iter prev(const Iter& begin, const std::sentinel_for<Iter> auto& end) const
		{
			auto match = std::ranges::search(begin, end, elements.crbegin(), elements.crend(), detail::patternCompare<std::iter_value_t<Iter>>).end();

			// This match will be one-after-the-end of the pattern, for consistency we need the first byte (from the beginning).
			match--;

			return match;
		}

		template <std::input_iterator Iter>
		[[nodiscard]] constexpr bool doesMatch(const Iter& iter, const std::sentinel_for<Iter> auto& end = std::unreachable_sentinel_t{}) const
		{
			std::input_iterator auto iterEnd = iter;
			for (std::size_t i = 0; i < elements.size(); i++) {
				if (iterEnd == end)
					return false;
				iterEnd++;
			}
			return std::equal(iter, iterEnd, elements.cbegin(), elements.end(), detail::patternCompare<std::iter_value_t<Iter>>);
		}
	};

	const char DEFAULT_DELIMITER = ' ';
	const char DEFAULT_WILDCARD = '?';

	template <detail::TemplateString String, char Delimiter = DEFAULT_DELIMITER, char Wildcard = DEFAULT_WILDCARD>
	consteval auto buildBytePattern()
	{
		std::array<PatternElement, detail::countWords<String>(Delimiter)> signature;

		detail::buildSignature(String, detail::ArrayInserter(signature), Delimiter, Wildcard);

		return signature;
	}

	constexpr auto buildBytePattern(std::string_view string, char delimiter = DEFAULT_DELIMITER, char wildcard = DEFAULT_WILDCARD)
	{
		std::vector<PatternElement> signature;

		detail::buildSignature(string, std::back_inserter(signature), delimiter, wildcard);

		return signature;
	}

	template <detail::TemplateString String, bool IncludeTerminator = true, char Wildcard = DEFAULT_WILDCARD>
	consteval auto buildStringPattern()
	{
		std::array<PatternElement, String.size() + (IncludeTerminator ? 1 : 0)> signature;

		for (std::size_t i = 0; i < String.size(); i++)
			if (String[i] == Wildcard)
				signature[i] = std::nullopt;
			else
				signature[i] = static_cast<InnerPatternElement>(String[i]);

		if constexpr (IncludeTerminator)
			signature[signature.size() - 1] = static_cast<InnerPatternElement>('\0');

		return signature;
	}

	constexpr auto buildStringPattern(std::string_view string, bool includeTerminator = true, char wildcard = DEFAULT_WILDCARD)
	{
		std::vector<PatternElement> signature;
		signature.reserve(string.size() + (includeTerminator ? 1 : 0));

		for (char c : string)
			if (c == wildcard)
				signature.emplace_back(std::nullopt);
			else
				signature.emplace_back(static_cast<InnerPatternElement>(c));

		if (includeTerminator)
			signature.emplace_back(static_cast<InnerPatternElement>('\0'));

		return signature;
	}
}

#endif
