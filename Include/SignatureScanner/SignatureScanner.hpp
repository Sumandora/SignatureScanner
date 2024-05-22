#ifndef SIGNATURESCANNER_HPP
#define SIGNATURESCANNER_HPP

#include <iterator>

namespace SignatureScanner {
	class Signature {
	public:
		template <typename Self, typename Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr auto next(this Self&& self, const Iter& begin, const Sent& end)
		{
			return self.next(begin, end);
		}

		template <typename Self, typename Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr auto prev(this Self&& self, const Iter& begin, const Sent& end)
		{
			return self.prev(begin, end);
		}

		template <typename Self, typename Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr bool doesMatch(this Self&& self, const Iter& iter, const Sent& end = std::unreachable_sentinel_t{})
		{
			return self.doesMatch(iter, end);
		}

		template <typename Self, typename Iter, typename Sent, typename Inserter>
		[[nodiscard]] constexpr auto all(this Self&& self, Iter begin, const Sent& end, Inserter inserter)
		{
			while (true) {
				auto it = self.next(begin, end);
				if (it == end)
					break;
				*inserter = it;
				begin = it;
				begin++;
			}
		}
	};
}

#endif
