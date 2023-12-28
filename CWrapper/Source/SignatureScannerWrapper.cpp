#include "SignatureScanner.hpp"
#include "SignatureScanner.h"

using namespace SignatureScanner;

extern "C" {

void* signaturescanner_createStringSignature(const char* string) {
	return new StringSignature{ string };
}

void* signaturescanner_createByteSignature(const char* bytes, char wildcard) {
	return new ByteSignature{ bytes, wildcard };
}

void* signaturescanner_createXRefSignature(const void* address, bool relativeReferences, bool absoluteReferences) {
	return new XRefSignature{ address, relativeReferences, absoluteReferences };
}


void signaturescanner_constructStringSignature(void* signature, const char* string) {
	new (signature) StringSignature { string };
}
extern size_t sizeofStringSignature = sizeof(StringSignature);

void signaturescanner_constructByteSignature(void* signature, const char* bytes, char wildcard) {
	new (signature) ByteSignature{ bytes, wildcard };
}
extern size_t sizeofByteSignature = sizeof(ByteSignature);

void signaturescanner_constructXRefSignature(void* signature, const void* address, bool relativeReferences, bool absoluteReferences) {
	new (signature) XRefSignature{ address, relativeReferences, absoluteReferences };
}
extern size_t sizeofXRefSignature = sizeof(XRefSignature);


uintptr_t signaturescanner_next(const void* signature, uintptr_t begin) {
	auto opt = static_cast<const Signature*>(signature)->findNext<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin);
	if(!opt.has_value())
		return NULL;
	return opt.value();
}
uintptr_t signaturescanner_next_bounded(const void* signature, uintptr_t begin, uintptr_t end) {
	auto opt = static_cast<const Signature*>(signature)->findNext<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin, end);
	if(!opt.has_value())
		return NULL;
	return opt.value();
}

uintptr_t signaturescanner_prev(const void* signature, uintptr_t begin) {
	auto opt = static_cast<const Signature*>(signature)->findPrev<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin);
	if(!opt.has_value())
		return NULL;
	return opt.value();
}
uintptr_t signaturescanner_prev_bounded(const void* signature, uintptr_t begin, uintptr_t end) {
	auto opt = static_cast<const Signature*>(signature)->findPrev<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin, end);
	if(!opt.has_value())
		return NULL;
	return opt.value();
}

void signaturescanner_all(const void* signature, uintptr_t* arr, size_t* count, uintptr_t begin, uintptr_t end) {
	auto vector = static_cast<const Signature*>(signature)->findAll<std::uintptr_t, std::uintptr_t, std::uintptr_t>(begin, end);
	arr = (uintptr_t*)malloc((*count = vector.size()) * sizeof(uintptr_t)); // Don't use new, since using free for objects created with new is UB

	for(std::size_t i = 0; i < vector.size(); i++)
		arr[i] = vector[i];
}


bool signaturescanner_pattern_doesMatch(const void* signature, uintptr_t addr) {
	return static_cast<const PatternSignature*>(signature)->doesMatch(addr);
}

bool signaturescanner_xref_doesMatch(const void* signature, uintptr_t addr, size_t space) {
	return static_cast<const XRefSignature*>(signature)->doesMatch(addr, space);
}


void signaturescanner_free(void* signature) {
	delete static_cast<Signature*>(signature);
}
void signaturescanner_cleanup(void* signature) {
	static_cast<Signature*>(signature)->Signature::~Signature();
}

}
