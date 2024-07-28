#ifndef SIGNATURESCANNER_HPP
#define SIGNATURESCANNER_HPP

#include <iterator>

namespace SignatureScanner {
	class Signature {
	public:
		template <std::input_iterator Iter>
		[[nodiscard]] constexpr Iter next(this auto&& self, const Iter& begin, const std::sentinel_for<Iter> auto& end)
		{
			return self.next(begin, end);
		}

		template <std::input_iterator Iter>
		[[nodiscard]] constexpr Iter prev(this auto&& self, const Iter& begin, const std::sentinel_for<Iter> auto& end)
		{
			return self.prev(begin, end);
		}

		template <std::input_iterator Iter>
		[[nodiscard]] constexpr bool doesMatch(this auto&& self, const Iter& iter, const std::sentinel_for<Iter> auto& end = std::unreachable_sentinel_t{})
		{
			return self.doesMatch(iter, end);
		}

		template <std::input_iterator Iter>
		constexpr void all(this auto&& self, Iter begin, const std::sentinel_for<Iter> auto& end, std::output_iterator<Iter> auto inserter)
		{
			while (true) {
				auto it = self.next(begin, end);
				if (it == end)
					break;
				*inserter++ = it;
				begin = it;
				begin++;
			}
		}
	};
}

#endif
