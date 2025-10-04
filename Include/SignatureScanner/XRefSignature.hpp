#ifndef SIGNATURESCANNER_XREFSIGNATURE_HPP
#define SIGNATURESCANNER_XREFSIGNATURE_HPP

#include "SignatureConcept.hpp"

#include "detail/ByteConverter.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <type_traits>
#include <variant>

namespace SignatureScanner {
	enum class XRefTypes : std::uint8_t {
		RELATIVE,
		ABSOLUTE,
		RELATIVE_AND_ABSOLUTE,
	};

	template <XRefTypes Types>
	class XRefSignature {
		static_assert(std::endian::native == std::endian::little || std::endian::native == std::endian::big, "Mixed endian is not supported");

		static constexpr bool IS_ABSOLUTE = Types == XRefTypes::ABSOLUTE || Types == XRefTypes::RELATIVE_AND_ABSOLUTE;
		static constexpr bool IS_RELATIVE = Types == XRefTypes::RELATIVE || Types == XRefTypes::RELATIVE_AND_ABSOLUTE;

		using RelAddrType = std::conditional_t<sizeof(void*) == 8, std::int32_t, std::int16_t>;

		const std::uintptr_t address;
		[[no_unique_address]] const std::conditional_t<IS_RELATIVE, std::uint8_t, std::monostate> instruction_length;

	public:
		explicit constexpr XRefSignature(std::uintptr_t address)
			requires(Types == XRefTypes::ABSOLUTE)
			: address(address)
			, instruction_length()
		{
		}

		explicit constexpr XRefSignature(std::uintptr_t address, std::uint8_t instruction_length = 4)
			requires(Types != XRefTypes::ABSOLUTE)
			: address(address)
			, instruction_length(instruction_length)
		{
		}

	private:
		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr Iter unoptimized_next(Iter it, const Sent& end, std::uintptr_t location) const
		{
			for (; it != end; it++)
				if (does_match(it, end, location++))
					return it;

			return it;
		}

		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr Iter unoptimized_prev(Iter it, const Sent& end, std::uintptr_t location) const
		{
			for (; it != end; it++) {
				// Regarding the "- 1":
				// ```
				// For a reverse iterator r constructed from an iterator i, the relationship &*r == &*(i - 1)
				// is always true (as long as r is dereferenceable); thus a reverse iterator constructed from
				// a one-past-the-end iterator dereferences to the last element in a sequence.
				// ```
				// https://en.cppreference.com/w/cpp/iterator/reverse_iterator
				if (does_match(std::make_reverse_iterator(it) - 1, std::make_reverse_iterator(end) - 1, location--))
					return it;
			}

			return it;
		}

#ifdef SIGNATURESCANNER_OPTIMIZE
		const std::byte* optimized_next(const std::byte* it, const std::byte* end, std::uintptr_t location) const;
		const std::byte* optimized_prev(const std::byte* it, const std::byte* end, std::uintptr_t location) const;
#endif

	public:
		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr Iter next(Iter it, const Sent& end) const
		{
			return next(it, end, reinterpret_cast<std::uintptr_t>(std::to_address(it)));
		}

		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr Iter prev(Iter it, const Sent& end) const
		{
			return prev(it, end, reinterpret_cast<std::uintptr_t>(std::to_address(it)));
		}

		template <std::input_iterator Iter>
		[[nodiscard]] constexpr bool does_match(const Iter& iter, const std::sentinel_for<Iter> auto& end) const
		{
			return does_match(iter, end, reinterpret_cast<std::uintptr_t>(std::to_address(iter)));
		}

		template <std::input_iterator Iter>
		constexpr void all(Iter begin, const std::sentinel_for<Iter> auto& end, std::output_iterator<Iter> auto inserter)
		{
			return all(begin, end, inserter, reinterpret_cast<std::uintptr_t>(std::to_address(begin)));
		}

		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr Iter next(Iter it, const Sent& end, std::uintptr_t location) const
		{
#ifdef SIGNATURESCANNER_OPTIMIZE
			if constexpr (std::contiguous_iterator<Iter> && std::contiguous_iterator<Sent> && sizeof(std::iter_value_t<Iter>) == 1) {
				const auto* it_ptr = reinterpret_cast<const std::byte*>(std::to_address(it));
				const auto* end_ptr = reinterpret_cast<const std::byte*>(std::to_address(end));

				auto match_dist = optimized_next(it_ptr, end_ptr, location) - it_ptr;
				return std::next(it, match_dist);
			}
#endif
			return unoptimized_next(it, end, location);
		}

		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr Iter prev(Iter it, const Sent& end, std::uintptr_t location) const
		{
#ifdef SIGNATURESCANNER_OPTIMIZE
			if constexpr (std::contiguous_iterator<Iter> && std::contiguous_iterator<Sent> && sizeof(std::iter_value_t<Iter>) == 1) {
				const auto* it_ptr = reinterpret_cast<const std::byte*>(std::to_address(it));
				const auto* end_ptr = reinterpret_cast<const std::byte*>(std::to_address(end));

				auto match_dist = optimized_prev(it_ptr, end_ptr, location) - it_ptr;
				return std::next(it, match_dist);
			}
#endif
			return unoptimized_prev(it, end, location);
		}

		template <std::input_iterator Iter>
		[[nodiscard]] constexpr bool does_match(const Iter& iter, const std::sentinel_for<Iter> auto& end, std::uintptr_t location) const
		{
			if constexpr (IS_ABSOLUTE)
				if (auto bytes = detail::convert_bytes<std::uintptr_t>(iter, end))
					if (does_absolute_match(bytes.value()))
						return true;

			if constexpr (IS_RELATIVE)
				if (auto bytes = detail::convert_bytes<RelAddrType>(iter, end))
					if (does_relative_match(bytes.value(), location))
						return true;

			return false;
		}

		[[nodiscard]] constexpr bool does_match(std::uintptr_t number, std::uintptr_t location) const
		{
			if constexpr (IS_ABSOLUTE)
				if (does_absolute_match(number))
					return true;

			if constexpr (IS_RELATIVE)
				if (does_relative_match(static_cast<RelAddrType>(number), location))
					return true;

			return false;
		}

		template <std::input_iterator Iter>
		constexpr void all(Iter begin, const std::sentinel_for<Iter> auto& end, std::output_iterator<Iter> auto inserter, std::uintptr_t location) const
		{
			Iter current = begin;
			while (true) {
				auto it = this->next(current, end, location);
				if (it == end)
					break;
				*inserter++ = it;

				location += std::distance(current, it) + 1;
				current = it;
				current++;
			}
		}

		[[nodiscard]] constexpr static bool is_absolute()
		{
			return IS_ABSOLUTE;
		}

		[[nodiscard]] constexpr static bool is_relative()
		{
			return IS_RELATIVE;
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

	using RelativeXRefSignature = XRefSignature<XRefTypes::RELATIVE>;
	using AbsoluteXRefSignature = XRefSignature<XRefTypes::ABSOLUTE>;
	using RelativeAndAbsoluteXRefSignature = XRefSignature<XRefTypes::RELATIVE_AND_ABSOLUTE>;

	static_assert(Signature<RelativeXRefSignature>);
	static_assert(Signature<AbsoluteXRefSignature>);
	static_assert(Signature<RelativeAndAbsoluteXRefSignature>);
}

#endif
