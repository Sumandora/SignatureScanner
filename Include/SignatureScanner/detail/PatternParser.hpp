#ifndef SIGNATURESCANNER_DETAIL_PATTERNPARSER_HPP
#define SIGNATURESCANNER_DETAIL_PATTERNPARSER_HPP

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>

namespace SignatureScanner {
	using PatternElement = std::optional<std::byte>;

	namespace detail {
		template <typename T>
		constexpr bool patternCompare(const T& byte, const PatternElement& elem)
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

		constexpr PatternElement buildWord(std::string_view word, char wildcard)
		{
			if (std::ranges::all_of(word, [wildcard](char c) { return c == wildcard; }))
				return PatternElement{ std::nullopt };

			return PatternElement{ static_cast<std::byte>(strToHex(word)) };
		}

		template <std::ranges::input_range Range>
			requires std::same_as<char, std::ranges::range_value_t<Range>>
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
}

#endif