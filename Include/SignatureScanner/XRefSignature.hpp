#ifndef SIGNATURESCANNER_XREFSIGNATURE_HPP
#define SIGNATURESCANNER_XREFSIGNATURE_HPP

#include "detail/AllMixin.hpp"
#include "detail/ByteConverter.hpp"
#include "detail/SignatureConcept.hpp"

#include <bit>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <type_traits>

namespace SignatureScanner {
	class XRefTypes : public std::bitset<2> {
		enum Index : std::uint8_t {
			RELATIVE = 0,
			ABSOLUTE = 1
		};

	public:
		[[nodiscard]] constexpr bool is_relative() const
		{
			return test(RELATIVE);
		}

		[[nodiscard]] constexpr bool is_absolute() const
		{
			return test(ABSOLUTE);
		}

		constexpr static XRefTypes relative()
		{
			XRefTypes types;
			types.set(RELATIVE, true);
			types.set(ABSOLUTE, false);
			return types;
		}

		constexpr static XRefTypes absolute()
		{
			XRefTypes types;
			types.set(RELATIVE, false);
			types.set(ABSOLUTE, true);
			return types;
		}

		constexpr static XRefTypes relative_and_absolute()
		{
			XRefTypes types;
			types.set(RELATIVE, true);
			types.set(ABSOLUTE, true);
			return types;
		}
	};

	class XRefSignature : public detail::AllMixin {
		static_assert(std::endian::native == std::endian::little || std::endian::native == std::endian::big, "Mixed endian is not supported");

		using RelAddrType = std::conditional_t<sizeof(void*) == 8, std::int32_t, std::int16_t>;

		const std::uintptr_t address;
		const bool absolute;
		const std::uint8_t instruction_length; // If instruction_length == 0 then relative search is disabled

	public:
		explicit constexpr XRefSignature(XRefTypes types, std::uintptr_t address, std::uint8_t instruction_length = 4)
			: address(address)
			, absolute(types.is_absolute())
			, instruction_length(types.is_relative() ? instruction_length : 0)
		{
		}

	private:
#ifdef SIGNATURESCANNER_OPTIMIZE
		const std::byte* optimized_next(const std::byte* it, const std::byte* end) const;
		const std::byte* optimized_prev(const std::byte* it, const std::byte* end) const;
#endif

	public:
		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr Iter next(Iter it, const Sent& end) const
		{
#ifdef SIGNATURESCANNER_OPTIMIZE
			if constexpr (std::contiguous_iterator<Iter> && std::contiguous_iterator<Sent> && sizeof(std::iter_value_t<Iter>) == 1) {
				const auto* it_ptr = reinterpret_cast<const std::byte*>(std::to_address(it));
				const auto* end_ptr = reinterpret_cast<const std::byte*>(std::to_address(end));

				auto match_dist = optimized_next(it_ptr, end_ptr) - it_ptr;
				return std::next(it, match_dist);
			}
#endif
			for (; it != end; it++)
				if (does_match(it, end))
					return it;

			return it;
		}

		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr Iter prev(Iter it, const Sent& end) const
		{
#ifdef SIGNATURESCANNER_OPTIMIZE
			if constexpr (std::contiguous_iterator<Iter> && std::contiguous_iterator<Sent> && sizeof(std::iter_value_t<Iter>) == 1) {
				const auto* it_ptr = reinterpret_cast<const std::byte*>(std::to_address(it));
				const auto* end_ptr = reinterpret_cast<const std::byte*>(std::to_address(end));

				auto match_dist = optimized_prev(it_ptr, end_ptr) - it_ptr;
				return std::next(it, match_dist);
			}
#endif
			for (; it != end; it++) {
				// Regarding the "- 1":
				// ```
				// For a reverse iterator r constructed from an iterator i, the relationship &*r == &*(i - 1)
				// is always true (as long as r is dereferenceable); thus a reverse iterator constructed from
				// a one-past-the-end iterator dereferences to the last element in a sequence.
				// ```
				// https://en.cppreference.com/w/cpp/iterator/reverse_iterator
				if (does_match(std::make_reverse_iterator(it) - 1, std::make_reverse_iterator(end) - 1))
					return it;
			}

			return it;
		}

		template <std::input_iterator Iter>
		[[nodiscard]] constexpr bool does_match(const Iter& iter, const std::sentinel_for<Iter> auto& end = std::unreachable_sentinel_t{}) const
		{
			if (is_absolute())
				if (auto bytes = detail::convert_bytes<std::uintptr_t>(iter, end))
					if (does_absolute_match(bytes.value()))
						return true;

			if (is_relative())
				if (auto bytes = detail::convert_bytes<RelAddrType>(iter, end))
					if (does_relative_match(bytes.value(), reinterpret_cast<std::uintptr_t>(&*iter)))
						return true;

			return false;
		}

		[[nodiscard]] constexpr bool does_match(std::uintptr_t number, std::uintptr_t location) const
		{
			if (is_absolute())
				if (does_absolute_match(number))
					return true;

			if (is_relative())
				if (does_relative_match(static_cast<RelAddrType>(number), location))
					return true;

			return false;
		}

		[[nodiscard]] constexpr bool is_absolute() const
		{
			return absolute;
		}

		[[nodiscard]] constexpr bool is_relative() const
		{
			return instruction_length > 0;
		}

		[[nodiscard]] constexpr bool does_absolute_match(std::uintptr_t number) const
		{
			return number == address;
		}

		[[nodiscard]] constexpr bool does_relative_match(RelAddrType offset, std::uintptr_t location) const
		{
			// This is special, when the address has 0x00 bytes in front of it, then offset is zero,
			// so location + instruction_length + 0. This usually happens when XRefs are searched in data sections.
			// There shouldn't be a need for this, so it is prevented here.
			if (offset == 0)
				return false;
			return location + instruction_length + offset == address;
		}
	};

	static_assert(detail::Signature<XRefSignature>);
}

#endif
