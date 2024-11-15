#ifndef SIGNATURESCANNER_PATTERNSIGNATURE_HPP
#define SIGNATURESCANNER_PATTERNSIGNATURE_HPP

#include "detail/AllMixin.hpp"
#include "detail/PatternBuilder.hpp"
#include "detail/PatternParser.hpp"
#include "detail/SignatureConcept.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <memory>
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

	private:
#ifdef SIGNATURESCANNER_OPTIMIZE
		const std::byte* optimizedNext(const std::byte* begin, const std::byte* end) const;
		const std::byte* optimizedPrev(const std::byte* begin, const std::byte* end) const;
#endif

	public:
		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr Iter next(const Iter& begin, const Sent& end) const
		{
#ifdef SIGNATURESCANNER_OPTIMIZE
			if constexpr (std::contiguous_iterator<Iter> && std::contiguous_iterator<Sent> && sizeof(std::iter_value_t<Iter>) == 1) {
				const auto* beginPtr = reinterpret_cast<const std::byte*>(std::to_address(begin));
				const auto* endPtr = reinterpret_cast<const std::byte*>(std::to_address(end));

				auto matchDist = optimizedNext(beginPtr, endPtr) - beginPtr;
				return std::next(begin, matchDist);
			}
#endif
			return std::ranges::search(begin, end, elements.cbegin(), elements.cend(), detail::patternCompare<std::iter_value_t<Iter>>).begin();
		}

		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr Iter prev(const Iter& begin, const Sent& end) const
		{
			Iter match;
#ifdef SIGNATURESCANNER_OPTIMIZE
			if constexpr (std::contiguous_iterator<Iter> && std::contiguous_iterator<Sent> && sizeof(std::iter_value_t<Iter>) == 1) {
				const auto* beginPtr = reinterpret_cast<const std::byte*>(std::to_address(begin));
				const auto* endPtr = reinterpret_cast<const std::byte*>(std::to_address(end));

				auto matchDist = optimizedPrev(beginPtr, endPtr) - beginPtr;
				match = std::next(begin, matchDist);
			} else
#endif
				match = std::ranges::search(begin, end, elements.crbegin(), elements.crend(), detail::patternCompare<std::iter_value_t<Iter>>).end();

			if (match != end)
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
