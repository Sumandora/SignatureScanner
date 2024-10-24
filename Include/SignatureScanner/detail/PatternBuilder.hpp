#ifndef SIGNATURESCANNER_DETAIL_PATTERNCREATOR_HPP
#define SIGNATURESCANNER_DETAIL_PATTERNCREATOR_HPP

#include "SignatureScanner/detail/ArrayInserter.hpp"
#include "SignatureScanner/detail/PatternParser.hpp"

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
		consteval auto buildBytePattern()
		{
			static constexpr auto countWords = [] {
				bool wasChar = false;

				std::size_t count = 0;
				for (char c : String) {
					bool isChar = c != Delimiter;
					if (!wasChar && isChar)
						count++;

					wasChar = isChar;
				}

				return count;
			};
			std::array<PatternElement, countWords()> signature;

			buildSignature(String, ArrayInserter(signature), Delimiter, Wildcard);

			return signature;
		}

		constexpr auto buildBytePattern(std::string_view string, char delimiter = DEFAULT_DELIMITER, char wildcard = DEFAULT_WILDCARD)
		{
			std::vector<PatternElement> signature;

			buildSignature(string, std::back_inserter(signature), delimiter, wildcard);

			return signature;
		}

		template <TemplateString String, bool IncludeTerminator = true, char Wildcard = DEFAULT_WILDCARD>
		consteval auto buildStringPattern()
		{
			std::array<PatternElement, String.size() + (IncludeTerminator ? 1 : 0)> signature;

			for (std::size_t i = 0; i < String.size(); i++)
				if (String[i] == Wildcard)
					signature[i] = std::nullopt;
				else
					signature[i] = static_cast<std::byte>(String[i]);

			if constexpr (IncludeTerminator)
				signature[signature.size() - 1] = static_cast<std::byte>('\0');

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
					signature.emplace_back(static_cast<std::byte>(c));

			if (includeTerminator)
				signature.emplace_back(static_cast<std::byte>('\0'));

			return signature;
		}

	}
}

#endif
