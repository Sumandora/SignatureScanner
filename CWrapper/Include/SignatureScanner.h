#ifndef SIGNATURESCANNER_H
#define SIGNATURESCANNER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

extern struct signaturescanner_impl {
	struct {
		size_t string_signature;
		size_t byte_signature;
		size_t xref_signature;
	} size_of;

	struct {
		void(*string)(void* signature, const char* string);
		void(*string_with_wildcard)(void* signature, const char* string, char wildcard);
		void(*ida_style)(void* signature, const char* bytes, char wildcard);
		void(*code_style)(void* signature, const char* bytes, const char* mask, char maskChar);
		void(*xref)(void* signature, const void* address, bool relativeReferences, bool absoluteReferences);
	} construct;

	struct {
		uintptr_t(*next)(const void* signature, uintptr_t begin);
		uintptr_t(*next_bounded)(const void* signature, uintptr_t begin, uintptr_t end);

		uintptr_t(*prev)(const void* signature, uintptr_t begin);
		uintptr_t(*prev_bounded)(const void* signature, uintptr_t begin, uintptr_t end);

		void(*all)(const void* signature, uintptr_t* arr, size_t* count, uintptr_t begin, uintptr_t end);
	} search;

	struct {
		bool(*pattern)(const void* signature, uintptr_t addr);
		bool(*xref)(const void* signature, uintptr_t addr, size_t space);
	} does_match;

	void(*cleanup)(void* signature);
} signature_scanner;

#ifdef __cplusplus
}
#endif

#endif
