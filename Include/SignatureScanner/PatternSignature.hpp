#ifndef SIGNATURESCANNER_PATTERNSIGNATURE_HPP
#define SIGNATURESCANNER_PATTERNSIGNATURE_HPP

#include "detail/SignatureConcept.hpp"
#include "detail/PatternBuilder.hpp"
#include "detail/PatternParser.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <string_view>
#include <utility>
#include <vector>

namespace SignatureScanner {
	class PatternSignature {
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
		static PatternSignature for_array_of_bytes()
		{
			static constexpr auto PATTERN = detail::build_byte_pattern<String, Delimiter, Wildcard>();

			return PatternSignature{ PATTERN };
		}

		static PatternSignature for_array_of_bytes(std::string_view string, char delimiter = DEFAULT_DELIMITER, char wildcard = DEFAULT_WILDCARD)
		{
			auto pattern = detail::build_byte_pattern(string, delimiter, wildcard);

			return PatternSignature{ std::move(pattern) };
		}

		template <detail::TemplateString String, bool IncludeTerminator = true, char Wildcard = DEFAULT_WILDCARD>
		static PatternSignature for_literal_string()
		{
			static constexpr auto PATTERN = detail::build_string_pattern<String, IncludeTerminator, Wildcard>();

			return PatternSignature{ PATTERN };
		}

		static PatternSignature for_literal_string(std::string_view string, bool include_terminator = true, char wildcard = DEFAULT_WILDCARD)
		{
			auto pattern = detail::build_string_pattern(string, include_terminator, wildcard);

			return PatternSignature{ std::move(pattern) };
		}

		[[nodiscard]] constexpr const std::vector<PatternElement>& get_elements() const { return elements; }

#ifdef SIGNATURESCANNER_OPTIMIZE
	private:
		const std::byte* optimized_next(const std::byte* begin, const std::byte* end) const;
		const std::byte* optimized_prev(const std::byte* begin, const std::byte* end) const;

	public:
#endif

		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr Iter next(const Iter& begin, const Sent& end) const
		{
#ifdef SIGNATURESCANNER_OPTIMIZE
			if constexpr (std::contiguous_iterator<Iter> && std::contiguous_iterator<Sent> && sizeof(std::iter_value_t<Iter>) == 1) {
				const auto* begin_ptr = reinterpret_cast<const std::byte*>(std::to_address(begin));
				const auto* end_ptr = reinterpret_cast<const std::byte*>(std::to_address(end));

				auto match_dist = optimized_next(begin_ptr, end_ptr) - begin_ptr;
				return std::next(begin, match_dist);
			}
#endif
			return std::ranges::search(begin, end, elements.cbegin(), elements.cend(), detail::pattern_compare<std::iter_value_t<Iter>>).begin();
		}

		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr Iter prev(const Iter& begin, const Sent& end) const
		{
			Iter match;
#ifdef SIGNATURESCANNER_OPTIMIZE
			if constexpr (std::contiguous_iterator<Iter> && std::contiguous_iterator<Sent> && sizeof(std::iter_value_t<Iter>) == 1) {
				const auto* begin_ptr = reinterpret_cast<const std::byte*>(std::to_address(begin));
				const auto* end_ptr = reinterpret_cast<const std::byte*>(std::to_address(end));

				auto match_dist = optimized_prev(begin_ptr, end_ptr) - begin_ptr;
				match = std::next(begin, match_dist);
			} else
#endif
				match = std::ranges::search(begin, end, elements.crbegin(), elements.crend(), detail::pattern_compare<std::iter_value_t<Iter>>).end();

			if (match != end)
				// This match will be one-after-the-end of the pattern, for consistency we need the first byte (from the beginning).
				match--;

			return match;
		}

		template <std::input_iterator Iter>
		constexpr void all(Iter begin, const std::sentinel_for<Iter> auto& end, std::output_iterator<Iter> auto inserter) const
		{
			while (true) {
				auto it = this->next(begin, end);
				if (it == end)
					break;
				*inserter++ = it;
				begin = it;
				begin++;
			}
		}

		template <std::input_iterator Iter>
		[[nodiscard]] constexpr bool does_match(const Iter& iter, const std::sentinel_for<Iter> auto& end = std::unreachable_sentinel_t{}) const
		{
			std::input_iterator auto iter_end = iter;
			for (std::size_t i = 0; i < elements.size(); i++) {
				if (iter_end == end)
					return false;
				iter_end++;
			}
			return std::equal(iter, iter_end, elements.cbegin(), elements.end(), detail::pattern_compare<std::iter_value_t<Iter>>);
		}
	};

	static_assert(detail::Signature<PatternSignature>);
}

#endif
