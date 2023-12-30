#ifndef SIGNATURESCANNER_H
#define SIGNATURESCANNER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// New Signatures
extern size_t sizeofStringSignature;
extern size_t sizeofByteSignature;
extern size_t sizeofXRefSignature;
// Note: when reusing allocated memory you still need to clean up the old memory
void signaturescanner_constructStringSignature(void* signature, const char* string);
void signaturescanner_constructStringSignature_wildcard(void* signature, const char* string, char wildcard);
void signaturescanner_constructByteSignature(void* signature, const char* bytes, char wildcard);
void signaturescanner_constructByteSignature_codeStyle(void* signature, const char* bytes, const char* mask, char maskChar);
void signaturescanner_constructXRefSignature(void* signature, const void* address, bool relativeReferences, bool absoluteReferences);

// Search
uintptr_t signaturescanner_next(const void* signature, uintptr_t begin);
uintptr_t signaturescanner_next_bounded(const void* signature, uintptr_t begin, uintptr_t end);

uintptr_t signaturescanner_prev(const void* signature, uintptr_t begin);
uintptr_t signaturescanner_prev_bounded(const void* signature, uintptr_t begin, uintptr_t end);

void signaturescanner_all(const void* signature, uintptr_t* arr, size_t* count, uintptr_t begin, uintptr_t end);

// Does Match
bool signaturescanner_pattern_doesMatch(const void* signature, uintptr_t addr);
bool signaturescanner_xref_doesMatch(const void* signature, uintptr_t addr, size_t space);

// Tear-down
void signaturescanner_cleanup(void* signature);

#ifdef __cplusplus
}
#endif

#endif
