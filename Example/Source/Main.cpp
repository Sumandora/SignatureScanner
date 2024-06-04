#include "SignatureScanner/PatternSignature.hpp"
#include "SignatureScanner/XRefSignature.hpp"

#include <cstring>
#include <gtest/gtest.h>
#include <span>

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
std::span<std::byte> bytesSpan{ reinterpret_cast<std::byte*>(bytes), sizeof(bytes) };

TEST(BytePattern, Forwards)
{
	PatternSignature signature = IDA::build<"e4">();
	auto hit = signature.next(bytesSpan.begin(), bytesSpan.end());

	EXPECT_NE(hit, bytesSpan.end());
	std::size_t offset = std::distance(bytesSpan.begin(), hit);
	EXPECT_EQ(offset, 42);
}

TEST(BytePattern, Backwards)
{
	PatternSignature signature = IDA::build<"e4">();
	auto hit = signature.prev(bytesSpan.rbegin(), bytesSpan.rend());

	EXPECT_NE(hit, bytesSpan.rend());
	std::size_t offset = std::distance(bytesSpan.rbegin(), hit);
	EXPECT_EQ(offset, 26);
}

TEST(BytePattern, All)
{
	PatternSignature signature = IDA::build<"a9">();
	std::vector<decltype(bytesSpan)::iterator> hits;
	signature.all(bytesSpan.begin(), bytesSpan.end(), std::back_inserter(hits));

	EXPECT_EQ(hits.size(), 3);
	EXPECT_EQ(std::distance(bytesSpan.begin(), hits[0]), 51);
	EXPECT_EQ(std::distance(bytesSpan.begin(), hits[1]), 91);
	EXPECT_EQ(std::distance(bytesSpan.begin(), hits[2]), 97);
}

std::string string = "The Answer to the Great Question Of Life, the Universe and Everything Is Forty-two";
std::span<std::byte> stringSpan{ reinterpret_cast<std::byte*>(string.data()), string.size() };

TEST(StringPattern, Forwards)
{
	PatternSignature signature = String::build<"Forty-two", false>();
	auto hit = signature.next(stringSpan.begin(), stringSpan.end());

	EXPECT_NE(hit, stringSpan.end());
	std::size_t offset = std::distance(stringSpan.begin(), hit);
	EXPECT_EQ(offset, 73);
}

TEST(StringPattern, Backwards)
{
	PatternSignature signature = String::build<"Forty-two", false>();
	auto hit = signature.prev(stringSpan.rbegin(), stringSpan.rend());

	EXPECT_NE(hit, stringSpan.rend());
	std::size_t offset = std::distance(stringSpan.rbegin(), hit);
	EXPECT_EQ(offset, 0);
}

TEST(StringPattern, All)
{
	PatternSignature signature = String::build<" ?? ", false>();
	std::vector<decltype(stringSpan)::iterator> hits;
	signature.all(stringSpan.begin(), stringSpan.end(), std::back_inserter(hits));

	EXPECT_EQ(hits.size(), 3);
	EXPECT_EQ(std::distance(stringSpan.begin(), hits[0]), 10);
	EXPECT_EQ(std::distance(stringSpan.begin(), hits[1]), 32);
	EXPECT_EQ(std::distance(stringSpan.begin(), hits[2]), 69);
}

std::uintptr_t target = 0x13371337;

std::uint8_t absoluteXRef[]{
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

std::uint8_t relativeXRef[]{
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

std::span<std::byte> absolutePadded{ reinterpret_cast<std::byte*>(absoluteXRef), sizeof(absoluteXRef) };
std::span<std::byte> absoluteUnpadded{ reinterpret_cast<std::byte*>(absoluteXRef) + 8, sizeof(absoluteXRef) - 16 };
std::span<std::byte> relativePadded{ reinterpret_cast<std::byte*>(relativeXRef), sizeof(relativeXRef) };
std::span<std::byte> relativeUnpadded{ reinterpret_cast<std::byte*>(relativeXRef) + 8, sizeof(relativeXRef) - 16 };

void initXRefArray()
{
	std::size_t offset = 8;

	memcpy(absoluteXRef + offset, &target, sizeof(void*));

	auto base = reinterpret_cast<std::uintptr_t>(relativeXRef + offset + 4);
	auto pTarget = reinterpret_cast<std::uintptr_t>(&target);
	std::size_t distance = std::max(pTarget, base) - std::min(pTarget, base);
	auto jmpTarget = static_cast<std::int32_t>(distance);
	if (base > pTarget)
		jmpTarget *= -1;
	std::memcpy(relativeXRef + offset, &jmpTarget, sizeof(std::int32_t));
}

TEST(XRefPattern, AbsoluteForwardsPadded)
{
	initXRefArray();

	auto signature = XRefSignature<false, true>{ target };
	auto hit = signature.next(absolutePadded.begin(), absolutePadded.end());

	EXPECT_NE(hit, absolutePadded.end());
	std::size_t offset = std::distance(absolutePadded.begin(), hit);
	EXPECT_EQ(offset, 8);
}

TEST(XRefPattern, RelativeForwardsPadded)
{
	initXRefArray();

	auto signature = XRefSignature<true, false>{ reinterpret_cast<std::uintptr_t>(&target) };
	auto hit = signature.next(relativePadded.begin(), relativePadded.end());

	EXPECT_NE(hit, relativePadded.end());
	std::size_t offset = std::distance(relativePadded.begin(), hit);
	EXPECT_EQ(offset, 8);
}

TEST(XRefPattern, AbsoluteForwardsUnpadded)
{
	initXRefArray();

	auto signature = XRefSignature<false, true>{ target };
	auto hit = signature.next(absoluteUnpadded.begin(), absoluteUnpadded.end());

	EXPECT_NE(hit, absoluteUnpadded.end());
	std::size_t offset = std::distance(absoluteUnpadded.begin(), hit);
	EXPECT_EQ(offset, 0);
}

TEST(XRefPattern, RelativeForwardsUnpadded)
{
	initXRefArray();

	auto signature = XRefSignature<true, false>{ reinterpret_cast<std::uintptr_t>(&target) };
	auto hit = signature.next(relativeUnpadded.begin(), relativeUnpadded.end());

	EXPECT_NE(hit, relativeUnpadded.end());
	std::size_t offset = std::distance(relativeUnpadded.begin(), hit);
	EXPECT_EQ(offset, 0);
}

TEST(XRefPattern, AbsoluteBackwardsPadded)
{
	initXRefArray();

	auto signature = XRefSignature<false, true>{ target };
	auto hit = signature.prev(absolutePadded.rbegin(), absolutePadded.rend());

	EXPECT_NE(hit, absolutePadded.rend());
	std::size_t offset = std::distance(absolutePadded.rbegin(), hit);
	EXPECT_EQ(offset, 15);
}

TEST(XRefPattern, RelativeBackwardsPadded)
{
	initXRefArray();

	auto signature = XRefSignature<true, false>{ reinterpret_cast<std::uintptr_t>(&target) };
	auto hit = signature.prev(relativePadded.rbegin(), relativePadded.rend());

	EXPECT_NE(hit, relativePadded.rend());
	std::size_t offset = std::distance(relativePadded.rbegin(), hit);
	EXPECT_EQ(offset, 11);
}

TEST(XRefPattern, AbsoluteBackwardsUnpadded)
{
	initXRefArray();

	auto signature = XRefSignature<false, true>{ target };
	auto hit = signature.prev(absoluteUnpadded.rbegin(), absoluteUnpadded.rend());

	EXPECT_NE(hit, absoluteUnpadded.rend());
	std::size_t offset = std::distance(absoluteUnpadded.rbegin(), hit);
	EXPECT_EQ(offset, 7);
}

TEST(XRefPattern, RelativeBackwardsUnpadded)
{
	initXRefArray();

	auto signature = XRefSignature<true, false>{ reinterpret_cast<std::uintptr_t>(&target) };
	auto hit = signature.prev(relativeUnpadded.rbegin(), relativeUnpadded.rend());

	EXPECT_NE(hit, relativeUnpadded.rend());
	std::size_t offset = std::distance(relativeUnpadded.rbegin(), hit);
	EXPECT_EQ(offset, 3);
}

TEST(XRefPattern, All)
{
	initXRefArray();

	auto absoluteSig = XRefSignature<false, true>{ target };
	auto relativeSig = XRefSignature<true, false>{ reinterpret_cast<std::uintptr_t>(&target) };
	std::vector<decltype(absolutePadded)::iterator> hits;
	absoluteSig.all(absolutePadded.begin(), absolutePadded.end(), std::back_inserter(hits));
	relativeSig.all(relativePadded.begin(), relativePadded.end(), std::back_inserter(hits));

	EXPECT_EQ(hits.size(), 2);
	EXPECT_EQ(reinterpret_cast<void*>(&*hits[0]), absoluteXRef + 8);
	EXPECT_EQ(reinterpret_cast<void*>(&*hits[1]), relativeXRef + 8);
}
