#ifndef SIGNATURESCANNER_HPP
#define SIGNATURESCANNER_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace SignatureScanner {
	namespace detail {
		using InnerPatternElement = std::byte;
		using PatternElement = std::optional<InnerPatternElement>;

		template <typename T>
		constexpr auto patternCompare(const T& byte, const detail::PatternElement& elem)
		{
			return !elem.has_value() || elem.value() == byte;
		}

		/**
		 * This thing is pretty much useless outside of this use-case,
		 * because the array could be partially filled up when we get it,
		 * for our use-case this doesn't matter.
		 */
		template <typename T, std::size_t N>
		struct ArrayInserter {
			std::array<T, N>& array;
			std::size_t idx = 0;

			constexpr explicit ArrayInserter(std::array<T, N>& array)
				: array(array)
			{
			}

			constexpr ArrayInserter& operator=(T obj)
			{
				array[idx] = obj;
				idx++;
				return *this;
			}

			constexpr ArrayInserter& operator*()
			{
				return *this;
			}
			constexpr ArrayInserter& operator++()
			{
				return *this;
			}
			constexpr ArrayInserter& operator++(int)
			{
				return *this;
			}
		};

		template <std::size_t N>
		struct TemplateString : std::array<char, N> {
#pragma clang diagnostic push
#pragma ide diagnostic ignored "google-explicit-constructor"
			constexpr TemplateString(const char (&str)[N + 1])
				: std::array<char, N>()
			{
				std::copy(std::begin(str), std::end(str) - 1, ArrayInserter(*this));
			}
#pragma clang diagnostic pop
		};

		template <std::size_t N>
		TemplateString(const char (&str)[N]) -> TemplateString<N - 1>;
	}

	namespace IDA {
		namespace ida_detail {
			constexpr uint8_t chrToHex(char c)
			{
				if ('0' <= c && c <= '9') {
					return c - '0';
				} else if ('A' <= c && c <= 'F') {
					return c - 'A' + 10;
				} else if ('a' <= c && c <= 'f') {
					return c - 'a' + 10;
				}
				return 0;
			}

			constexpr uint8_t strToHex(std::string_view input)
			{
				uint8_t val = 0;
				for (char c : input) {
					val *= 16;
					val += chrToHex(c);
				}
				return val;
			}

			template <detail::TemplateString string>
			constexpr std::size_t countWords(char delimiter)
			{
				bool wasChar = false;

				std::size_t count = 0;
				for (char c : string) {
					bool isChar = c != delimiter;
					if (!wasChar && isChar)
						count++;

					wasChar = c != delimiter;
				}

				return count;
			}

			constexpr detail::PatternElement buildWord(std::string_view word, char wildcard)
			{
				if (std::ranges::all_of(word, [wildcard](char c) { return c == wildcard; }))
					return std::nullopt;
				else
					return static_cast<detail::InnerPatternElement>(strToHex(word));
			}

			template <typename Range, typename Inserter>
			constexpr void buildSignature(const Range& range, Inserter inserter, char Delimiter, char Wildcard)
			{
				std::string word;

				std::size_t idx = 0;
				for (char c : range)
					if (c == Delimiter) {
						if (word.empty())
							continue;

						inserter = buildWord(word, Wildcard);
						idx++;

						word = "";
					} else
						word += c;

				if (!word.empty())
					inserter = buildWord(word, Wildcard);
			}
		}

		const char DEFAULT_DELIMITER = ' ';
		const char DEFAULT_WILDCARD = '?';

		template <detail::TemplateString String, char Delimiter = DEFAULT_DELIMITER, char Wildcard = DEFAULT_WILDCARD>
		consteval auto build()
		{
			constexpr std::size_t Length = ida_detail::countWords<String>(Delimiter);

			std::array<detail::PatternElement, Length> signature;

			ida_detail::buildSignature(String, detail::ArrayInserter(signature), Delimiter, Wildcard);

			return signature;
		}

		constexpr auto build(std::string_view string, char delimiter = DEFAULT_DELIMITER, char wildcard = DEFAULT_WILDCARD)
		{
			std::vector<detail::PatternElement> signature;

			ida_detail::buildSignature(string, std::back_inserter(signature), delimiter, wildcard);

			return signature;
		}
	}

	namespace String {
		const char DEFAULT_WILDCARD = '?';

		template <detail::TemplateString String, bool IncludeTerminator = true, char Wildcard = DEFAULT_WILDCARD>
		consteval auto build()
		{
			std::array<detail::PatternElement, IncludeTerminator ? String.size() + 1 : String.size()> signature;

			for (size_t i = 0; i < String.size(); i++)
				if (String[i] == Wildcard)
					signature[i] = std::nullopt;
				else
					signature[i] = static_cast<detail::InnerPatternElement>(String[i]);

			if constexpr (IncludeTerminator)
				signature[signature.size() - 1] = (static_cast<detail::InnerPatternElement>('\0'));

			return signature;
		}

		constexpr auto build(std::string_view string, bool includeTerminator = true, char wildcard = DEFAULT_WILDCARD)
		{
			std::vector<detail::PatternElement> signature;
			signature.reserve(string.size() + (includeTerminator ? 1 : 0));

			for (char c : string)
				if (c == wildcard)
					signature.emplace_back(std::nullopt);
				else
					signature.emplace_back(static_cast<detail::InnerPatternElement>(c));

			if (includeTerminator)
				signature.emplace_back(static_cast<detail::InnerPatternElement>('\0'));

			return signature;
		}
	}

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

		template <typename Self, typename Iter>
		[[nodiscard]] constexpr bool doesMatch(this Self&& self, const Iter& iter)
		{
			return self.doesMatch(iter);
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

	template <std::size_t N>
	class PatternSignature : public Signature {
	private:
		std::array<detail::PatternElement, N> elements;

	public:
		static constexpr std::size_t Length = N;
		constexpr PatternSignature(std::array<detail::PatternElement, N>&& elements)
			: elements(std::move(elements))
		{
		}

		[[nodiscard]] constexpr const std::array<detail::PatternElement, N>& getElements() const { return elements; }

		template <typename Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr auto next(const Iter& begin, const Sent& end) const
		{
			return std::ranges::search(begin, end, elements.cbegin(), elements.cend(), detail::patternCompare<decltype(*std::declval<Iter>())>).begin();
		}

		template <typename Iter, std::sentinel_for<Iter> Sent>
		[[nodiscard]] constexpr auto prev(const Iter& begin, const Sent& end) const
		{
			return std::ranges::search(begin, end, elements.crbegin(), elements.crend(), detail::patternCompare<decltype(*std::declval<Iter>())>).begin();
		}

		template <typename Iter>
		[[nodiscard]] constexpr bool doesMatch(const Iter& iter) const
		{
			return std::equal(elements.cbegin(), iter.cbegin(), elements.cend(), std::next(iter.cbegin(), elements.length()), detail::patternCompare<decltype(*std::declval<Iter>())>);
		}
	};

	namespace detail {
		template <typename T, std::endian Endianness, typename Iter, std::sentinel_for<Iter> Sent>
		constexpr std::optional<T> convertBytes(Iter iter, const Sent& end)
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
		template <typename Iter, typename Sent>
		[[nodiscard]] constexpr auto next(Iter it, const Sent& end) const
		{
			for (; it != end; it++)
				if (doesMatch(it, end))
					return it;

			return it;
		}

		template <typename Iter, typename Sent>
		[[nodiscard]] constexpr auto prev(Iter it, const Sent& end) const
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

		template <typename Iter, std::sentinel_for<Iter> Sent = std::unreachable_sentinel_t>
		[[nodiscard]] constexpr bool doesMatch(const Iter& iter, const Sent& end = std::unreachable_sentinel_t{}) const
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
			// This is a special which I encountered if the address has 0x00 bytes before it, thus it becomes location + instructionLength + 0.
			// I can't imagine a case in which this is desired.
			if (offset == 0)
				return false;
			return location + instructionLength + offset == address;
		}
	};
}

#endif
