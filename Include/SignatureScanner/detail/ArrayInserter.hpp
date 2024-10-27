#ifndef SIGNATURESCANNER_DETAIL_ARRAYINSERTER_HPP
#define SIGNATURESCANNER_DETAIL_ARRAYINSERTER_HPP

#include <array>
#include <cstddef>

namespace SignatureScanner::detail {
	/**
	 * This thing is pretty much useless outside of this use-case,
	 * because the array could be partially filled up when it is passed here
	 */
	template <typename T, std::size_t N>
	struct ArrayInserter {
		using difference_type = std::ptrdiff_t;

		std::array<T, N>* array;
		std::size_t idx = 0;

		constexpr explicit ArrayInserter(std::array<T, N>& array)
			: array(&array)
		{
		}

		constexpr ArrayInserter& operator=(T obj)
		{
			(*array)[idx] = obj;
			return *this;
		}

		constexpr ArrayInserter& operator*()
		{
			return *this;
		}
		constexpr ArrayInserter& operator++()
		{
			idx++;
			return *this;
		}
		constexpr ArrayInserter operator++(int)
		{
			ArrayInserter it = *this;
			idx++;
			return it;
		}
	};
}

#endif
