#include "SignatureScanner.hpp"
#include "SignatureScanner.h"

using namespace SignatureScanner;

extern "C" {

size_t sigscan_sizeof_string = sizeof(StringSignature);
size_t sigscan_sizeof_byte = sizeof(ByteSignature);
size_t sigscan_sizeof_xref = sizeof(XRefSignature);

void sigscan_construct_string(void* signature, const char* string) {
	new (signature) StringSignature { string };
}
void sigscan_construct_string_with_wildcard(void* signature, const char* string, char wildcard) {
	new (signature) StringSignature { string, wildcard };
}
void sigscan_construct_ida_style(void* signature, const char* bytes, char wildcard) {
	new (signature) ByteSignature{ bytes, wildcard };
}
void sigscan_construct_code_style(void* signature, const char* bytes, const char* mask, char maskChar) {
	new (signature) ByteSignature{ bytes, mask, maskChar };
}
void sigscan_construct_xref(void* signature, const void* address, bool relativeReferences, bool absoluteReferences) {
	new (signature) XRefSignature{ address, relativeReferences, absoluteReferences };
}


uintptr_t sigscan_next(const void* signature, uintptr_t begin) {
	auto opt = static_cast<const Signature*>(signature)->findNext<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin);
	if(!opt.has_value())
		return NULL;
	return opt.value();
}
uintptr_t sigscan_next_bounded(const void* signature, uintptr_t begin, uintptr_t end) {
	auto opt = static_cast<const Signature*>(signature)->findNext<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin, end);
	if(!opt.has_value())
		return NULL;
	return opt.value();
}

uintptr_t sigscan_prev(const void* signature, uintptr_t begin) {
	auto opt = static_cast<const Signature*>(signature)->findPrev<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin);
	if(!opt.has_value())
		return NULL;
	return opt.value();
}
uintptr_t sigscan_prev_bounded(const void* signature, uintptr_t begin, uintptr_t end) {
	auto opt = static_cast<const Signature*>(signature)->findPrev<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin, end);
	if(!opt.has_value())
		return NULL;
	return opt.value();
}

void sigscan_all(const void* signature, uintptr_t* arr, size_t* count, uintptr_t begin, uintptr_t end) {
	auto vector = static_cast<const Signature*>(signature)->findAll<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin, end);
	arr = (uintptr_t*)malloc((*count = vector.size()) * sizeof(uintptr_t)); // Don't use new, since using free for objects created with new is UB

	for(std::size_t i = 0; i < vector.size(); i++)
		arr[i] = vector[i];
}


bool sigscan_pattern_does_match(const void* signature, uintptr_t addr) {
	return static_cast<const PatternSignature*>(signature)->doesMatch(addr);
}

bool sigscan_xref_does_match(const void* signature, uintptr_t addr, size_t space) {
	return static_cast<const XRefSignature*>(signature)->doesMatch(addr, space);
}


void sigscan_cleanup(void* signature) {
	static_cast<Signature*>(signature)->Signature::~Signature();
}

}
