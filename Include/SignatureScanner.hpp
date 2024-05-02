#ifndef SIGNATURESCANNER_HPP
#define SIGNATURESCANNER_HPP

#include <algorithm>
#include <array>
#include <cstdint>
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
				std::copy(std::begin(str), std::end(str) - 1, ArrayInserter<char, N>(*this));
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
				for (char c : range) {
					if (c == Delimiter) {
						if (word.empty())
							continue;

						inserter = buildWord(word, Wildcard);
						idx++;

						word = "";
					} else
						word += c;
				}

				if (!word.empty()) {
					inserter = buildWord(word, Wildcard);
				}
			}
		}

		const char DEFAULT_DELIMITER = ' ';
		const char DEFAULT_WILDCARD = '?';

		template <detail::TemplateString String, char Delimiter = DEFAULT_DELIMITER, char Wildcard = DEFAULT_WILDCARD, std::size_t Length = ida_detail::countWords<String>(Delimiter)>
		consteval auto build()
		{
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

			for (size_t i = 0; i < String.size(); i++) {
				if (String[i] == Wildcard)
					signature[i] = std::nullopt;
				else
					signature[i] = static_cast<detail::InnerPatternElement>(String[i]);
			}

			if constexpr (IncludeTerminator) {
				signature[signature.size() - 1] = (static_cast<detail::InnerPatternElement>('\0'));
			}

			return signature;
		}

		constexpr auto build(std::string_view string, bool includeTerminator = true, char wildcard = DEFAULT_WILDCARD)
		{
			std::vector<detail::PatternElement> signature;
			signature.reserve(string.size() + (includeTerminator ? 1 : 0));

			for (char c : string) {
				if (c == wildcard)
					signature.emplace_back(std::nullopt);
				else
					signature.emplace_back(static_cast<detail::InnerPatternElement>(c));
			}

			if (includeTerminator) {
				signature.emplace_back(static_cast<detail::InnerPatternElement>('\0'));
			}

			return signature;
		}
	}

	template <typename Derived>
	class Signature {
	public:
		template <typename Iter, typename Sent, typename Inserter>
		[[nodiscard]] constexpr auto all(Iter begin, const Sent& end, Inserter inserter) const
		{
			while (true) {
				auto it = static_cast<const Derived*>(this)->next(begin, end);
				if (it == end)
					break;
				*inserter = it;
				begin = it;
				begin++;
			}
		}
	};

	template <std::size_t N>
	class PatternSignature : public Signature<PatternSignature<N>> {
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
		[[nodiscard]] constexpr bool doesMatch(const Iter& addr) const
		{
			return std::equal(elements.cbegin(), addr.cbegin(), elements.cend(), std::next(addr.cbegin(), elements.length()), detail::patternCompare<decltype(*std::declval<Iter>())>);
		}
	};

	namespace detail {
		template <std::size_t N>
		struct StaticQueue : std::array<std::byte, N> {
			using std::array<std::byte, N>::array;

			constexpr StaticQueue(std::array<std::byte, N> arr)
				: std::array<std::byte, N>(arr)
			{
			}

			constexpr void push_front(std::byte b)
			{
				for (std::size_t i = N - 1; i > 0; i--)
					(*this)[i] = (*this)[i - 1];
				(*this)[0] = b;
			}

			constexpr void push_back(std::byte b)
			{
				for (std::size_t i = 1; i < N; i++)
					(*this)[i - 1] = (*this)[i];
				(*this)[N - 1] = b;
			}

			template <std::size_t NewN>
			constexpr std::array<std::byte, NewN> sliced(std::size_t offset = 0)
				requires(NewN <= N)
			{
				std::array<std::byte, NewN> arr;
				for (std::size_t i = 0; i < NewN; i++)
					arr[i] = (*this)[offset + i];
				return arr;
			}
		};

		template <typename T, std::size_t N>
		constexpr T convertBytes(const std::array<std::byte, N> array, std::endian endianness)
		{
			T num = std::bit_cast<T>(array);
			if (endianness != std::endian::native)
				num = std::byteswap(num);
			return num;
		}
	}

	template <bool Relative = true, bool Absolute = true, std::endian Endianness = std::endian::native>
	class XRefSignature : public Signature<XRefSignature<Relative, Absolute, Endianness>> {
		static_assert(Relative || Absolute);

		using RelAddrType = std::conditional_t<sizeof(void*) == 8, std::int32_t, std::int16_t>;
		const std::uintptr_t address;
		[[no_unique_address]] const std::conditional_t<Relative, std::size_t, std::monostate> instructionLength;
		static constexpr std::size_t MAX_SLIDE_WINDOW_SIZE = Relative ? std::max(sizeof(std::uintptr_t), sizeof(RelAddrType)) : sizeof(std::uintptr_t);
		static constexpr std::size_t REL_OFFSET_SIZE = sizeof(RelAddrType);

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

	private:
		template <typename Iter, std::sentinel_for<Iter> Sent, bool Backwards>
		constexpr auto twoPointer(const Iter& begin, const Sent& end) const
		{
			auto range = std::ranges::subrange{ begin, end };

			detail::StaticQueue<MAX_SLIDE_WINDOW_SIZE> number{};

			auto p1 = begin;
			auto p2 = begin;

			std::size_t i = 0;
			std::size_t size = std::min(MAX_SLIDE_WINDOW_SIZE, static_cast<decltype(MAX_SLIDE_WINDOW_SIZE)>(std::distance(begin, end)));
			while (true) {
				if constexpr (Backwards) {
					if constexpr (Relative) {
						if constexpr (Endianness == std::endian::little) {
							number.push_front(*p2);
						} else {
							number.push_back(*p2);
						}

						if (i >= REL_OFFSET_SIZE - 1) {
							auto offset = detail::convertBytes<RelAddrType>(number.template sliced<REL_OFFSET_SIZE>(), Endianness);
							if (doesRelativeMatch(offset, reinterpret_cast<std::uintptr_t>(&*p2))) {
								return p2;
							}
						}
					} else // faster
						number[size - 1 - i] = *p2;
				} else {
					number[i] = *p2;
				}

				i++;

				if (i >= size)
					break;

				p2++;
			}

			if (size == MAX_SLIDE_WINDOW_SIZE)
				while (true) {
					auto offset = detail::convertBytes<std::uintptr_t>(number, Endianness);

					if constexpr (Absolute) {
						if (doesAbsoluteMatch(offset)) {
							if constexpr (Backwards) {
								return p2;
							} else {
								return p1;
							}
						}
					}

					if constexpr (Relative) {
						if constexpr (Backwards) {
							if (doesRelativeMatch(static_cast<RelAddrType>(offset), reinterpret_cast<std::uintptr_t>(&*p2)))
								return p2;
						} else {
							if (doesRelativeMatch(static_cast<RelAddrType>(offset), reinterpret_cast<std::uintptr_t>(&*p1)))
								return p1;
						}
					}

					p2++;

					if (p2 == end)
						break;

					p1++;

					if constexpr (Backwards == (Endianness == std::endian::little))
						number.push_front(*p2);
					else
						number.push_back(*p2);
				}

			if constexpr (!Backwards && Relative && REL_OFFSET_SIZE < MAX_SLIDE_WINDOW_SIZE) {
				i = 0;
				while (i <= size - REL_OFFSET_SIZE) {
					auto offset = detail::convertBytes<RelAddrType>(number.template sliced<REL_OFFSET_SIZE>(i), Endianness);

					if (doesRelativeMatch(offset, reinterpret_cast<std::uintptr_t>(&*p1)))
						return p1;

					p1++;
					i++;
				}
			}

			return end;
		}

	public:
		template <typename Iter, typename Sent>
		[[nodiscard]] constexpr auto next(const Iter& begin, const Sent& end) const
		{
			return twoPointer<Iter, Sent, false>(begin, end);
		}

		template <typename Iter, typename Sent>
		[[nodiscard]] constexpr auto prev(const Iter& begin, const Sent& end) const
		{
			return twoPointer<Iter, Sent, true>(begin, end);
		}

		template <typename Iter, std::sentinel_for<Iter> Sent = std::unreachable_sentinel_t>
		[[nodiscard]] constexpr bool doesMatch(const Iter& addr, const Sent& end = std::unreachable_sentinel_t{}) const
		{
			detail::StaticQueue<MAX_SLIDE_WINDOW_SIZE> number;
			std::size_t i = 0;
			std::uintptr_t location;
			for (auto it = addr; it != end; it++) {
				if constexpr (Endianness == std::endian::little)
					number.push_back(*it);
				else
					number.push_front(*it);
				i++;

				location = detail::convertBytes<std::uintptr_t>(number, Endianness);

				if constexpr (Relative) {
					if (i >= REL_OFFSET_SIZE && doesRelativeMatch(static_cast<RelAddrType>(number), location)) {
						return true;
					}
				}

				if (i >= MAX_SLIDE_WINDOW_SIZE)
					break;
			}

			if constexpr (Absolute) {
				if (i >= MAX_SLIDE_WINDOW_SIZE && doesAbsoluteMatch(location)) {
					return true;
				}
			}

			return false;
		}

		[[nodiscard]] constexpr bool doesMatch(std::uintptr_t number, std::conditional_t<Relative, std::uintptr_t, std::monostate> location = {}) const
		{
			if constexpr (Absolute) {
				if (doesAbsoluteMatch(number)) {
					return true;
				}
			}

			if constexpr (Relative) {
				if (doesRelativeMatch(static_cast<RelAddrType>(number), location)) {
					return true;
				}
			}
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
