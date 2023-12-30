#include "SignatureScanner.h"
#include "SignatureScanner.hpp"

using namespace SignatureScanner;

extern "C" {

	static void signaturescanner_constructStringSignature(void* signature, const char* string)
	{
		new (signature) StringSignature{ string };
	}
	static void signaturescanner_constructStringSignature_wildcard(void* signature, const char* string, char wildcard)
	{
		new (signature) StringSignature{ string, wildcard };
	}
	static void signaturescanner_constructByteSignature(void* signature, const char* bytes, char wildcard)
	{
		new (signature) ByteSignature{ bytes, wildcard };
	}
	static void signaturescanner_constructByteSignature_codeStyle(void* signature, const char* bytes, const char* mask, char maskChar)
	{
		new (signature) ByteSignature{ bytes, mask, maskChar };
	}
	static void signaturescanner_constructXRefSignature(void* signature, const void* address, bool relativeReferences, bool absoluteReferences)
	{
		new (signature) XRefSignature{ address, relativeReferences, absoluteReferences };
	}

	static uintptr_t signaturescanner_next(const void* signature, uintptr_t begin)
	{
		auto opt = static_cast<const Signature*>(signature)->findNext<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin);
		if (!opt.has_value())
			return NULL;
		return opt.value();
	}
	static uintptr_t signaturescanner_next_bounded(const void* signature, uintptr_t begin, uintptr_t end)
	{
		auto opt = static_cast<const Signature*>(signature)->findNext<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin, end);
		if (!opt.has_value())
			return NULL;
		return opt.value();
	}

	static uintptr_t signaturescanner_prev(const void* signature, uintptr_t begin)
	{
		auto opt = static_cast<const Signature*>(signature)->findPrev<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin);
		if (!opt.has_value())
			return NULL;
		return opt.value();
	}
	static uintptr_t signaturescanner_prev_bounded(const void* signature, uintptr_t begin, uintptr_t end)
	{
		auto opt = static_cast<const Signature*>(signature)->findPrev<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin, end);
		if (!opt.has_value())
			return NULL;
		return opt.value();
	}

	static void signaturescanner_all(const void* signature, uintptr_t* arr, size_t* count, uintptr_t begin, uintptr_t end)
	{
		auto vector = static_cast<const Signature*>(signature)->findAll<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin, end);
		arr = (uintptr_t*)malloc((*count = vector.size()) * sizeof(uintptr_t)); // Don't use new, since using free for objects created with new is UB

		for (std::size_t i = 0; i < vector.size(); i++)
			arr[i] = vector[i];
	}

	static bool signaturescanner_pattern_doesMatch(const void* signature, uintptr_t addr)
	{
		return static_cast<const PatternSignature*>(signature)->doesMatch(addr);
	}

	static bool signaturescanner_xref_doesMatch(const void* signature, uintptr_t addr, size_t space)
	{
		return static_cast<const XRefSignature*>(signature)->doesMatch(addr, space);
	}

	static void signaturescanner_free(void* signature)
	{
		delete static_cast<Signature*>(signature);
	}
	static void signaturescanner_cleanup(void* signature)
	{
		static_cast<Signature*>(signature)->Signature::~Signature();
	}

	struct signaturescanner_impl signature_scanner {
		{
			sizeof(StringSignature),
			sizeof(ByteSignature),
			sizeof(XRefSignature)
		},
			{ signaturescanner_constructStringSignature,
				signaturescanner_constructStringSignature_wildcard,
				signaturescanner_constructByteSignature,
				signaturescanner_constructByteSignature_codeStyle,
				signaturescanner_constructXRefSignature },
			{ signaturescanner_next,
				signaturescanner_next_bounded,
				signaturescanner_prev,
				signaturescanner_prev_bounded,
				signaturescanner_all },
			{ signaturescanner_pattern_doesMatch,
				signaturescanner_xref_doesMatch },
			signaturescanner_cleanup
	};
}
