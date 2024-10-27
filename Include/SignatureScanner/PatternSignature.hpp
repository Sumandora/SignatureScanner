#ifndef SIGNATURESCANNER_PATTERNSIGNATURE_HPP
#define SIGNATURESCANNER_PATTERNSIGNATURE_HPP

#include "SignatureScanner/detail/AllMixin.hpp"
#include "SignatureScanner/detail/PatternBuilder.hpp"
#include "SignatureScanner/detail/PatternParser.hpp"
#include "SignatureScanner/detail/SignatureConcept.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <string_view>
#include <utility>
#include <vector>

namespace SignatureScanner {
	class PatternSignature : public detail::AllMixin {
		std::vector<PatternElement> elements;

	public:
		explicit constexpr PatternSignature(std::vector<PatternElement>&& elements)
			: elements(std::move(elements))
		{
		}

		template <std::size_t N>
		explicit constexpr PatternSignature(const std::array<PatternElement, N>& elements)
			: elements(elements.begin(), elements.end())
		{
		}

		template <detail::TemplateString String, char Delimiter = DEFAULT_DELIMITER, char Wildcard = DEFAULT_WILDCARD>
		static PatternSignature fromBytes()
		{
			constexpr auto pattern = detail::buildBytePattern<String, Delimiter, Wildcard>();

			return PatternSignature{ pattern };
		}

		static PatternSignature fromBytes(std::string_view string, char delimiter = DEFAULT_DELIMITER, char wildcard = DEFAULT_WILDCARD)
		{
			auto pattern = detail::buildBytePattern(string, delimiter, wildcard);

			return PatternSignature{ std::move(pattern) };
		}

		template <detail::TemplateString String, bool IncludeTerminator = true, char Wildcard = DEFAULT_WILDCARD>
		static PatternSignature fromString()
		{
			constexpr auto pattern = detail::buildStringPattern<String, IncludeTerminator, Wildcard>();

			return PatternSignature{ pattern };
		}

		static PatternSignature fromString(std::string_view string, bool includeTerminator = true, char wildcard = DEFAULT_WILDCARD)
		{
			auto pattern = detail::buildStringPattern(string, includeTerminator, wildcard);

			return PatternSignature{ std::move(pattern) };
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

}

#endif
