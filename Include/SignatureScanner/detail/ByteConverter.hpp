#ifndef SIGNATURESCANNER_DETAIL_BYTECONVERTER
#define SIGNATURESCANNER_DETAIL_BYTECONVERTER

#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <iterator>
#include <optional>

namespace SignatureScanner::detail {
	template <std::integral T, std::input_iterator Iter>
	constexpr std::optional<T> convertBytes(Iter iter, const std::sentinel_for<Iter> auto& end)
	{
		std::array<std::byte, sizeof(T)> arr;
		for (std::size_t i = 0; i < sizeof(T); i++) {
			if (iter == end)
				return std::nullopt;
			if constexpr (std::assignable_from<decltype(arr[i]), std::iter_value_t<Iter>>) {
				arr[i] = *iter;
			} else if constexpr (requires() { std::bit_cast<std::byte>(*iter); }) {
				arr[i] = std::bit_cast<std::byte>(*iter);
			} else {
				static_assert(false, "Iter type is not a byte(-like) type");
			}
			iter++;
		}
		T num = std::bit_cast<T>(arr);
		if constexpr (std::endian::little != std::endian::native)
			num = std::byteswap(num);
		return num;
	}
}

#endif
