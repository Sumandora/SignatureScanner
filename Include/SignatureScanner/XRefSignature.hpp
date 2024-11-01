#ifndef SIGNATURESCANNER_XREFSIGNATURE_HPP
#define SIGNATURESCANNER_XREFSIGNATURE_HPP

#include "detail/ByteConverter.hpp"
#include "detail/AllMixin.hpp"
#include "detail/SignatureConcept.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <type_traits>

namespace SignatureScanner {
	class XRefSignature : public detail::AllMixin {
		static_assert(std::endian::native == std::endian::little || std::endian::native == std::endian::big, "Mixed endian is not supported");

		using RelAddrType = std::conditional_t<sizeof(void*) == 8, std::int32_t, std::int16_t>;

		const std::uintptr_t address;
		const bool absolute;
		const std::uint8_t instructionLength; // if instructionLength == 0 then relative search is disabled

	public:
		explicit constexpr XRefSignature(bool absolute, bool relative, std::uintptr_t address, std::uint8_t instructionLength = 4)
			: address(address)
			, absolute(absolute)
			, instructionLength(relative ? instructionLength : 0)
		{
		}

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
			if (isAbsolute())
				if (auto bytes = detail::convertBytes<std::uintptr_t>(iter, end))
					if (doesAbsoluteMatch(bytes.value()))
						return true;

			if (isRelative())
				if (auto bytes = detail::convertBytes<RelAddrType>(iter, end))
					if (doesRelativeMatch(bytes.value(), reinterpret_cast<std::uintptr_t>(&*iter)))
						return true;

			return false;
		}

		[[nodiscard]] constexpr bool doesMatch(std::uintptr_t number, std::uintptr_t location) const
		{
			if (isAbsolute())
				if (doesAbsoluteMatch(number))
					return true;

			if (isRelative())
				if (doesRelativeMatch(static_cast<RelAddrType>(number), location))
					return true;

			return false;
		}

		[[nodiscard]] constexpr bool isAbsolute() const
		{
			return absolute;
		}

		[[nodiscard]] constexpr bool isRelative() const
		{
			return instructionLength > 0;
		}

		[[nodiscard]] constexpr bool doesAbsoluteMatch(std::uintptr_t number) const
		{
			return number == address;
		}

		[[nodiscard]] constexpr bool doesRelativeMatch(RelAddrType offset, std::uintptr_t location) const
		{
			// This is special, when the address has 0x00 bytes in front of it, then offset is zero,
			// so location + instructionLength + 0. This usually happens when XRefs are searched in data sections.
			// There shouldn't be a need for this, so it is prevented here.
			if (offset == 0)
				return false;
			return location + instructionLength + offset == address;
		}
	};

	static_assert(detail::Signature<XRefSignature>);
}

#endif
