#ifndef SIGNATURESCANNER_DETAIL_PATTERNCREATOR_HPP
#define SIGNATURESCANNER_DETAIL_PATTERNCREATOR_HPP

#include "ArrayInserter.hpp"
#include "PatternParser.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <optional>
#include <string_view>
#include <vector>

namespace SignatureScanner {
	constexpr char DEFAULT_DELIMITER = ' ';
	constexpr char DEFAULT_WILDCARD = '?';

	namespace detail {

		template <std::size_t N>
		struct TemplateString : std::array<char, N - 1> {
			// NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
			constexpr TemplateString(const char (&str)[N])
				: std::array<char, N - 1>()
			{
				std::copy(std::begin(str), std::end(str) - 1, ArrayInserter(*this));
			}
		};

		template <TemplateString String, char Delimiter = DEFAULT_DELIMITER, char Wildcard = DEFAULT_WILDCARD>
		consteval auto build_byte_pattern()
		{
			static constexpr std::size_t WORD_COUNT = [] {
				bool was_char = false;

				std::size_t count = 0;
				for (char c : String) {
					bool is_char = c != Delimiter;
					if (!was_char && is_char)
						count++;

					was_char = is_char;
				}

				return count;
			}();
			std::array<PatternElement, WORD_COUNT> signature;

			build_signature(String, ArrayInserter(signature), Delimiter, Wildcard);

			return signature;
		}

		constexpr auto build_byte_pattern(std::string_view string, char delimiter = DEFAULT_DELIMITER, char wildcard = DEFAULT_WILDCARD)
		{
			std::vector<PatternElement> signature;

			build_signature(string, std::back_inserter(signature), delimiter, wildcard);

			return signature;
		}

		template <TemplateString String, bool IncludeTerminator = true, char Wildcard = DEFAULT_WILDCARD>
		consteval auto build_string_pattern()
		{
			std::array<PatternElement, String.size() + (IncludeTerminator ? 1 : 0)> signature;

			for (std::size_t i = 0; i < String.size(); i++) {
				if (String[i] == Wildcard)
					signature[i] = std::nullopt;
				else
					signature[i] = static_cast<std::byte>(String[i]);
			}

			if constexpr (IncludeTerminator)
				signature[signature.size() - 1] = static_cast<std::byte>('\0');

			return signature;
		}

		constexpr auto build_string_pattern(std::string_view string, bool include_terminator = true, char wildcard = DEFAULT_WILDCARD)
		{
			std::vector<PatternElement> signature;
			signature.reserve(string.size() + (include_terminator ? 1 : 0));

			for (char c : string)
				if (c == wildcard)
					signature.emplace_back(std::nullopt);
				else
					signature.emplace_back(static_cast<std::byte>(c));

			if (include_terminator)
				signature.emplace_back(static_cast<std::byte>('\0'));

			return signature;
		}

	}
}

#endif
