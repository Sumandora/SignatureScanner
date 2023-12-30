#ifndef SIGNATURESCANNER_H
#define SIGNATURESCANNER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// New Signatures
extern size_t sigscan_sizeof_string;
extern size_t sigscan_sizeof_byte;
extern size_t sigscan_sizeof_xref;
// Note: when reusing allocated memory you still need to clean up the old memory
void sigscan_construct_string(void* signature, const char* string);
void sigscan_construct_string_with_wildcard(void* signature, const char* string, char wildcard);
void sigscan_construct_ida_style(void* signature, const char* bytes, char wildcard);
void sigscan_construct_code_style(void* signature, const char* bytes, const char* mask, char maskChar);
void sigscan_construct_xref(void* signature, const void* address, bool relativeReferences, bool absoluteReferences);

// Search
uintptr_t sigscan_next(const void* signature, uintptr_t begin);
uintptr_t sigscan_next_bounded(const void* signature, uintptr_t begin, uintptr_t end);

uintptr_t sigscan_prev(const void* signature, uintptr_t begin);
uintptr_t sigscan_prev_bounded(const void* signature, uintptr_t begin, uintptr_t end);

void sigscan_all(const void* signature, uintptr_t* arr, size_t* count, uintptr_t begin, uintptr_t end);

// Does Match
bool sigscan_pattern_does_match(const void* signature, uintptr_t addr);
bool sigscan_xref_does_match(const void* signature, uintptr_t addr, size_t space);

// Tear-down
void sigscan_cleanup(void* signature);

#ifdef __cplusplus
}
#endif

#endif
