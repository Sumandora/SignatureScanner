#ifndef SIGNATURESCANNER_H
#define SIGNATURESCANNER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// New Signatures (These are heap allocated)
void* signaturescanner_createStringSignature(const char* string);
void* signaturescanner_createByteSignature(const char* bytes, char wildcard);
void* signaturescanner_createXRefSignature(const void* address, bool relativeReferences, bool absoluteReferences);

// New (stack allocated) Signatures
void signaturescanner_constructStringSignature(void* signature, const char* string);
extern size_t sizeofStringSignature;

void signaturescanner_constructByteSignature(void* signature, const char* bytes, char wildcard);
extern size_t sizeofByteSignature;

void signaturescanner_constructXRefSignature(void* signature, const void* address, bool relativeReferences, bool absoluteReferences);
extern size_t sizeofXRefSignature;

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
void signaturescanner_free(void* signature);
void signaturescanner_cleanup(void* signature);

#ifdef __cplusplus
}
#endif

#endif
