#ifndef SIGNATURESCANNER_HPP
#define SIGNATURESCANNER_HPP

#include <iterator>

namespace SignatureScanner {
	class Signature {
	public:
		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr auto next(this auto&& self, const Iter& begin, const Sent& end)
		{
			return self.next(begin, end);
		}

		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr auto prev(this auto&& self, const Iter& begin, const Sent& end)
		{
			return self.prev(begin, end);
		}

		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr bool doesMatch(this auto&& self, const Iter& iter, const Sent& end = std::unreachable_sentinel_t{})
		{
			return self.doesMatch(iter, end);
		}

		template <std::input_iterator Iter, std::sentinel_for<Iter> Sent, std::output_iterator<Iter> Inserter>
		[[nodiscard]] constexpr auto all(this auto&& self, Iter begin, const Sent& end, Inserter inserter)
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
