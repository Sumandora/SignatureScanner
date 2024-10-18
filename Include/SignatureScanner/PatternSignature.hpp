#ifndef SIGNATURESCANNER_PATTERNSIGNATURE_HPP
#define SIGNATURESCANNER_PATTERNSIGNATURE_HPP

#include "SignatureScanner/detail/SignatureConcept.hpp"
#include "SignatureScanner/detail/AllMixin.hpp"
#include "SignatureScanner/detail/PatternParser.hpp"
#include "SignatureScanner/detail/ArrayInserter.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace SignatureScanner {
	namespace detail {
		template <std::size_t N>
		struct TemplateString : std::array<char, N> {
			// NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
			constexpr TemplateString(const char (&str)[N])
				: std::array<char, N>()
			{
				std::copy(std::begin(str), std::end(str), ArrayInserter(*this));
			}
		};

		template <std::size_t N>
		TemplateString(const char (&str)[N]) -> TemplateString<N - 1>;
	}

	class PatternSignature : public detail::AllMixin {
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

	static_assert(detail::Signature<PatternSignature>);

	const char DEFAULT_DELIMITER = ' ';
	const char DEFAULT_WILDCARD = '?';

	template<detail::TemplateString String, char Delimiter = DEFAULT_DELIMITER, char Wildcard = DEFAULT_WILDCARD>
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

#endif
