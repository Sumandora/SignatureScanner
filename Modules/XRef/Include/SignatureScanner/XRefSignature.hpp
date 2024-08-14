#ifndef SIGNATURESCANNER_XREFSIGNATURE_HPP
#define SIGNATURESCANNER_XREFSIGNATURE_HPP

#include "SignatureScanner/SignatureScanner.hpp"

#include <bit>
#include <optional>
#include <variant>

namespace SignatureScanner {
	namespace detail {
		template <typename T, std::endian Endianness, std::input_iterator Iter>
		constexpr std::optional<T> convertBytes(Iter iter, const std::sentinel_for<Iter> auto& end)
		{
			std::array<std::byte, sizeof(T)> arr;
			for (std::size_t i = 0; i < sizeof(T); i++) {
				if (iter == end)
					return std::nullopt;
				arr[i] = *iter;
				iter++;
			}
			T num = std::bit_cast<T>(arr);
			if constexpr (Endianness != std::endian::native)
				num = std::byteswap(num);
			return num;
		}
	}

	template <bool Relative = true, bool Absolute = true, std::endian Endianness = std::endian::native>
	class XRefSignature : public Signature {
		static_assert(Relative || Absolute);

		using RelAddrType = std::conditional_t<sizeof(void*) == 8, std::int32_t, std::int16_t>;
		const std::uintptr_t address;
		[[no_unique_address]] const std::conditional_t<Relative, std::size_t, std::monostate> instructionLength;

	public:
		explicit constexpr XRefSignature(std::uintptr_t address, std::size_t instructionLength)
			requires Relative
			: address(address)
			, instructionLength(instructionLength)
		{
		}

		explicit constexpr XRefSignature(std::uintptr_t address)
			: address(address)
			, instructionLength([] {
				if constexpr (Relative)
					return sizeof(RelAddrType);
				else
					return decltype(instructionLength){};
			}())
		{
		}

	public:
		template <std::input_iterator Iter>
		[[nodiscard]] constexpr Iter next(Iter it, const std::sentinel_for<Iter> auto& end) const
		{
			for (; it != end; it++)
				if (doesMatch(it, end))
					return it;

			return it;
		}

		template <std::input_iterator Iter>
		[[nodiscard]] constexpr Iter prev(Iter it, const std::sentinel_for<Iter> auto& end) const
		{
			for (; it != end; it++) {
				// Regarding the "- 1":
				// For a reverse iterator r constructed from an iterator i, the relationship &*r == &*(i - 1)
				// is always true (as long as r is dereferenceable); thus a reverse iterator constructed from
				// a one-past-the-end iterator dereferences to the last element in a sequence.
				// https://en.cppreference.com/w/cpp/iterator/reverse_iterator
				if (doesMatch(std::make_reverse_iterator(it) - 1, std::make_reverse_iterator(end) - 1))
					return it;
			}

			return it;
		}

		template <std::input_iterator Iter>
		[[nodiscard]] constexpr bool doesMatch(const Iter& iter, const std::sentinel_for<Iter> auto& end = std::unreachable_sentinel_t{}) const
		{
			if constexpr (Absolute)
				if (auto bytes = detail::convertBytes<std::uintptr_t, Endianness>(iter, end); bytes.has_value())
					if (doesAbsoluteMatch(bytes.value()))
						return true;

			if constexpr (Relative)
				if (auto bytes = detail::convertBytes<RelAddrType, Endianness>(iter, end); bytes.has_value())
					if (doesRelativeMatch(bytes.value(), reinterpret_cast<std::uintptr_t>(&*iter)))
						return true;

			return false;
		}

		[[nodiscard]] constexpr bool doesMatch(std::uintptr_t number, std::conditional_t<Relative, std::uintptr_t, std::monostate> location = {}) const
		{
			if constexpr (Absolute)
				if (doesAbsoluteMatch(number))
					return true;

			if constexpr (Relative)
				if (doesRelativeMatch(static_cast<RelAddrType>(number), location))
					return true;

			return false;
		}

		[[nodiscard]] constexpr bool doesAbsoluteMatch(std::uintptr_t number) const
			requires Absolute
		{
			return number == address;
		}

		[[nodiscard]] constexpr bool doesRelativeMatch(RelAddrType offset, std::uintptr_t location) const
			requires Relative
		{
			// This is special, when the address has 0x00 bytes in front of it, then offset is zero,
			// so location + instructionLength + 0. This usually happens when XRefs are searched in data sections.
			// There shouldn't be a need for this, so it is prevented here.
			if (offset == 0)
				return false;
			return location + instructionLength + offset == address;
		}
	};
}

#endif
