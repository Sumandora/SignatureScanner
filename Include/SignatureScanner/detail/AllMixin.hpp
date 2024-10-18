#ifndef SIGNATURESCANNER_DETAIL_ALLMIXIN_HPP
#define SIGNATURESCANNER_DETAIL_ALLMIXIN_HPP

#include <iterator>

namespace SignatureScanner::detail {
	struct AllMixin {
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
