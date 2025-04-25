#include "SignatureScanner/PatternSignature.hpp"
#include "SignatureScanner/XRefSignature.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <span>
#include <string_view>
#include <vector>

using namespace SignatureScanner;

static std::uint8_t bytes[]{
	0x68, 0x74, 0x16, 0xcd, 0xaa, 0xe3, 0x6, 0x95, 0xcb, 0xeb, 0xe7,
	0x64, 0x1e, 0xbb, 0x5a, 0xf2, 0x65, 0xe5, 0x53, 0x85, 0xb8,
	0xfe, 0xb4, 0x3f, 0xb4, 0x38, 0x3a, 0x1a, 0xc4, 0x5f, 0x00,
	0x5e, 0x35, 0xe7, 0xd4, 0x3d, 0xb3, 0x51, 0x98, 0xa7, 0x66,
	0x1d, 0xe4, 0xff, 0x9a, 0x63, 0xa, 0x37, 0x6f, 0xd, 0x24,
	0xa9, 0x5c, 0x19, 0xb9, 0xa1, 0xfb, 0x91, 0x73, 0xd7, 0x3d,
	0xc, 0x9b, 0xb, 0xac, 0xd2, 0x49, 0x98, 0x2d, 0x8, 0x29,
	0xb6, 0xf0, 0x43, 0xe4, 0x7, 0x5, 0xfa, 0x30, 0x81, 0xc9,
	0xad, 0xaf, 0x7c, 0x8, 0xee, 0xca, 0xdf, 0xdb, 0x2c, 0x76,
	0xa9, 0x49, 0xb8, 0xf5, 0xcd, 0x4d, 0xa9, 0x14, 0xc0, 0xaf
};
static std::span<std::uint8_t> bytes_span{ bytes };

TEST(BytePattern, Forwards)
{
	const PatternSignature signature = PatternSignature::for_array_of_bytes<"e4">();
	auto hit = signature.next(bytes_span.begin(), bytes_span.end());

	EXPECT_NE(hit, bytes_span.end());
	const std::size_t offset = std::distance(bytes_span.begin(), hit);
	EXPECT_EQ(offset, 42);
}

TEST(BytePattern, Backwards)
{
	const PatternSignature signature = PatternSignature::for_array_of_bytes<"e4">();
	auto hit = signature.prev(bytes_span.rbegin(), bytes_span.rend());

	EXPECT_NE(hit, bytes_span.rend());
	const std::size_t offset = std::distance(bytes_span.rbegin(), hit);
	EXPECT_EQ(offset, 26);
}

TEST(BytePattern, All)
{
	const PatternSignature signature = PatternSignature::for_array_of_bytes<"a9">();
	std::vector<decltype(bytes_span)::iterator> hits;
	signature.all(bytes_span.begin(), bytes_span.end(), std::back_inserter(hits));

	EXPECT_EQ(hits.size(), 3);
	EXPECT_EQ(std::distance(bytes_span.begin(), hits[0]), 51);
	EXPECT_EQ(std::distance(bytes_span.begin(), hits[1]), 91);
	EXPECT_EQ(std::distance(bytes_span.begin(), hits[2]), 97);
}

// NOLINTNEXTLINE(cert-err58-cpp)
static std::string_view string = "The Answer to the Great Question Of Life, the Universe and Everything Is Forty-two";

TEST(StringPattern, Forwards)
{
	const PatternSignature signature = PatternSignature::for_literal_string<"Forty-two", false>();
	// NOLINTNEXTLINE(llvm-qualified-auto, readability-qualified-auto)
	auto hit = signature.next(string.begin(), string.end());

	EXPECT_NE(hit, string.end());
	const std::size_t offset = std::distance(string.begin(), hit);
	EXPECT_EQ(offset, 73);
}

TEST(StringPattern, Backwards)
{
	const PatternSignature signature = PatternSignature::for_literal_string<"Forty-two", false>();
	auto hit = signature.prev(string.rbegin(), string.rend());

	EXPECT_NE(hit, string.rend());
	const std::size_t offset = std::distance(string.rbegin(), hit);
	EXPECT_EQ(offset, 8);
}

TEST(StringPattern, All)
{
	const PatternSignature signature = PatternSignature::for_literal_string<" ?? ", false>();
	std::vector<decltype(string)::iterator> hits;
	signature.all(string.begin(), string.end(), std::back_inserter(hits));

	EXPECT_EQ(hits.size(), 3);
	EXPECT_EQ(std::distance(string.begin(), hits[0]), 10);
	EXPECT_EQ(std::distance(string.begin(), hits[1]), 32);
	EXPECT_EQ(std::distance(string.begin(), hits[2]), 69);
}

static std::uintptr_t target = 0x13371337;

static std::uint8_t absolute_xref[]{
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,

	0x00,
	0x00,
	0x00,
	0x00,
#ifdef __x86_64
	0x00,
	0x00,
	0x00,
	0x00,
#endif

	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
};

static std::uint8_t relative_xref[]{
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,

	0x00,
	0x00,
#ifdef __x86_64
	0x00,
	0x00,
#endif

	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
};

static std::span<std::uint8_t> absolute_ref{ absolute_xref };
static std::span<std::uint8_t> relative_ref{ relative_xref };

static void init_xref_array()
{
	const std::size_t offset = 8;

	memcpy(absolute_xref + offset, &target, sizeof(void*));

	auto base = reinterpret_cast<std::uintptr_t>(relative_xref + offset + 4);
	auto target_ptr = reinterpret_cast<std::uintptr_t>(&target);
	const std::size_t distance = std::max(target_ptr, base) - std::min(target_ptr, base);
	auto jmp_target = static_cast<std::int32_t>(distance);
	if (base > target_ptr)
		jmp_target *= -1;
	std::memcpy(relative_xref + offset, &jmp_target, sizeof(std::int32_t));
}

TEST(XRefPattern, AbsoluteForwards)
{
	init_xref_array();

	auto signature = XRefSignature{ XRefTypes::absolute(), target };
	auto hit = signature.next(absolute_ref.begin(), absolute_ref.end());

	EXPECT_NE(hit, absolute_ref.end());
	const std::size_t offset = std::distance(absolute_ref.begin(), hit);
	EXPECT_EQ(offset, 8);
}

TEST(XRefPattern, RelativeForwards)
{
	init_xref_array();

	auto signature = XRefSignature{ XRefTypes::relative(), reinterpret_cast<std::uintptr_t>(&target) };
	auto hit = signature.next(relative_ref.begin(), relative_ref.end());

	EXPECT_NE(hit, relative_ref.end());
	const std::size_t offset = std::distance(relative_ref.begin(), hit);
	EXPECT_EQ(offset, 8);
}

TEST(XRefPattern, AbsoluteBackwards)
{
	init_xref_array();

	auto signature = XRefSignature{ XRefTypes::absolute(), target };
	auto hit = signature.prev(absolute_ref.rbegin(), absolute_ref.rend());

	EXPECT_NE(hit, absolute_ref.rend());
	const std::size_t offset = std::distance(absolute_ref.rbegin(), hit);
	EXPECT_EQ(offset, 15);
}

TEST(XRefPattern, RelativeBackwards)
{
	init_xref_array();

	auto signature = XRefSignature{ XRefTypes::relative(), reinterpret_cast<std::uintptr_t>(&target) };
	auto hit = signature.prev(relative_ref.rbegin(), relative_ref.rend());

	EXPECT_NE(hit, relative_ref.rend());
	const std::size_t offset = std::distance(relative_ref.rbegin(), hit);
	EXPECT_EQ(offset, 11);
}

TEST(XRefPattern, All)
{
	init_xref_array();

	auto absolute_sig = XRefSignature{ XRefTypes::absolute(), target };
	auto relative_sig = XRefSignature{ XRefTypes::relative(), reinterpret_cast<std::uintptr_t>(&target) };
	std::vector<decltype(absolute_ref)::iterator> hits;
	absolute_sig.all(absolute_ref.begin(), absolute_ref.end(), std::back_inserter(hits));
	relative_sig.all(relative_ref.begin(), relative_ref.end(), std::back_inserter(hits));

	EXPECT_EQ(hits.size(), 2);
	EXPECT_EQ(reinterpret_cast<void*>(&*hits[0]), absolute_xref + 8);
	EXPECT_EQ(reinterpret_cast<void*>(&*hits[1]), relative_xref + 8);
}
