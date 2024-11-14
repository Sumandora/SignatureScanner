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
static std::span<std::uint8_t> bytesSpan{ bytes };

TEST(BytePattern, Forwards)
{
	const PatternSignature signature = PatternSignature::fromBytes<"e4">();
	auto hit = signature.next(bytesSpan.begin(), bytesSpan.end());

	EXPECT_NE(hit, bytesSpan.end());
	const std::size_t offset = std::distance(bytesSpan.begin(), hit);
	EXPECT_EQ(offset, 42);
}

TEST(BytePattern, Backwards)
{
	const PatternSignature signature = PatternSignature::fromBytes<"e4">();
	auto hit = signature.prev(bytesSpan.rbegin(), bytesSpan.rend());

	EXPECT_NE(hit, bytesSpan.rend());
	const std::size_t offset = std::distance(bytesSpan.rbegin(), hit);
	EXPECT_EQ(offset, 26);
}

TEST(BytePattern, All)
{
	const PatternSignature signature = PatternSignature::fromBytes<"a9">();
	std::vector<decltype(bytesSpan)::iterator> hits;
	signature.all(bytesSpan.begin(), bytesSpan.end(), std::back_inserter(hits));

	EXPECT_EQ(hits.size(), 3);
	EXPECT_EQ(std::distance(bytesSpan.begin(), hits[0]), 51);
	EXPECT_EQ(std::distance(bytesSpan.begin(), hits[1]), 91);
	EXPECT_EQ(std::distance(bytesSpan.begin(), hits[2]), 97);
}

// NOLINTNEXTLINE(cert-err58-cpp)
static std::string_view string = "The Answer to the Great Question Of Life, the Universe and Everything Is Forty-two";

TEST(StringPattern, Forwards)
{
	const PatternSignature signature = PatternSignature::fromString<"Forty-two", false>();
	// NOLINTNEXTLINE(llvm-qualified-auto, readability-qualified-auto)
	auto hit = signature.next(string.begin(), string.end());

	EXPECT_NE(hit, string.end());
	const std::size_t offset = std::distance(string.begin(), hit);
	EXPECT_EQ(offset, 73);
}

TEST(StringPattern, Backwards)
{
	const PatternSignature signature = PatternSignature::fromString<"Forty-two", false>();
	auto hit = signature.prev(string.rbegin(), string.rend());

	EXPECT_NE(hit, string.rend());
	const std::size_t offset = std::distance(string.rbegin(), hit);
	EXPECT_EQ(offset, 8);
}

TEST(StringPattern, All)
{
	const PatternSignature signature = PatternSignature::fromString<" ?? ", false>();
	std::vector<decltype(string)::iterator> hits;
	signature.all(string.begin(), string.end(), std::back_inserter(hits));

	EXPECT_EQ(hits.size(), 3);
	EXPECT_EQ(std::distance(string.begin(), hits[0]), 10);
	EXPECT_EQ(std::distance(string.begin(), hits[1]), 32);
	EXPECT_EQ(std::distance(string.begin(), hits[2]), 69);
}

static std::uintptr_t target = 0x13371337;

static std::uint8_t absoluteXRef[]{
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

static std::uint8_t relativeXRef[]{
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

static std::span<std::uint8_t> absoluteRef{ absoluteXRef };
static std::span<std::uint8_t> relativeRef{ relativeXRef };

static void initXRefArray()
{
	const std::size_t offset = 8;

	memcpy(absoluteXRef + offset, &target, sizeof(void*));

	auto base = reinterpret_cast<std::uintptr_t>(relativeXRef + offset + 4);
	auto pTarget = reinterpret_cast<std::uintptr_t>(&target);
	const std::size_t distance = std::max(pTarget, base) - std::min(pTarget, base);
	auto jmpTarget = static_cast<std::int32_t>(distance);
	if (base > pTarget)
		jmpTarget *= -1;
	std::memcpy(relativeXRef + offset, &jmpTarget, sizeof(std::int32_t));
}

TEST(XRefPattern, AbsoluteForwards)
{
	initXRefArray();

	auto signature = XRefSignature{ XRefTypes::absolute(), target };
	auto hit = signature.next(absoluteRef.begin(), absoluteRef.end());

	EXPECT_NE(hit, absoluteRef.end());
	const std::size_t offset = std::distance(absoluteRef.begin(), hit);
	EXPECT_EQ(offset, 8);
}

TEST(XRefPattern, RelativeForwards)
{
	initXRefArray();

	auto signature = XRefSignature{ XRefTypes::relative(), reinterpret_cast<std::uintptr_t>(&target) };
	auto hit = signature.next(relativeRef.begin(), relativeRef.end());

	EXPECT_NE(hit, relativeRef.end());
	const std::size_t offset = std::distance(relativeRef.begin(), hit);
	EXPECT_EQ(offset, 8);
}

TEST(XRefPattern, AbsoluteBackwards)
{
	initXRefArray();

	auto signature = XRefSignature{ XRefTypes::absolute(), target };
	auto hit = signature.prev(absoluteRef.rbegin(), absoluteRef.rend());

	EXPECT_NE(hit, absoluteRef.rend());
	const std::size_t offset = std::distance(absoluteRef.rbegin(), hit);
	EXPECT_EQ(offset, 15);
}

TEST(XRefPattern, RelativeBackwards)
{
	initXRefArray();

	auto signature = XRefSignature{ XRefTypes::relative(), reinterpret_cast<std::uintptr_t>(&target) };
	auto hit = signature.prev(relativeRef.rbegin(), relativeRef.rend());

	EXPECT_NE(hit, relativeRef.rend());
	const std::size_t offset = std::distance(relativeRef.rbegin(), hit);
	EXPECT_EQ(offset, 11);
}

TEST(XRefPattern, All)
{
	initXRefArray();

	auto absoluteSig = XRefSignature{ XRefTypes::absolute(), target };
	auto relativeSig = XRefSignature{ XRefTypes::relative(), reinterpret_cast<std::uintptr_t>(&target) };
	std::vector<decltype(absoluteRef)::iterator> hits;
	absoluteSig.all(absoluteRef.begin(), absoluteRef.end(), std::back_inserter(hits));
	relativeSig.all(relativeRef.begin(), relativeRef.end(), std::back_inserter(hits));

	EXPECT_EQ(hits.size(), 2);
	EXPECT_EQ(reinterpret_cast<void*>(&*hits[0]), absoluteXRef + 8);
	EXPECT_EQ(reinterpret_cast<void*>(&*hits[1]), relativeXRef + 8);
}
