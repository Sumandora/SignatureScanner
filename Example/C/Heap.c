#define _GNU_SOURCE
#include <assert.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>

#include "SignatureScanner.h"

void testByteSignatures()
{
	unsigned char byte_array_hex[] = {
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
	void* signature = malloc(sigscan_sizeof_byte);
	sigscan_construct_ida_style(signature, "1d e4 ff 9a 63 ?? 37 6f d 24", '?');

	uintptr_t hit = sigscan_next_bounded(signature, &byte_array_hex, &byte_array_hex + sizeof(byte_array_hex));
	assert(hit != NULL);

	size_t offset = hit - (uintptr_t)byte_array_hex;

	printf("Offset: %ld\n", offset);

	assert(offset == 41);

	sigscan_cleanup(signature);
	sigscan_construct_code_style(signature, "\x1e\xbb\x5a\xf2\x65\xe5\x53\x85", "xxxxxxxx", 'x');

	hit = sigscan_prev_bounded(signature, hit, byte_array_hex);
	assert(hit != NULL);

	offset = hit - (uintptr_t)byte_array_hex;
	printf("Offset: %ld\n", offset);
	assert(offset == 12);

	uintptr_t* ptr = NULL;
	size_t count;
	void* newSignature = malloc(sigscan_sizeof_byte);
	sigscan_construct_ida_style(newSignature, "a9", '?');
	sigscan_all(newSignature, ptr, &count, byte_array_hex, byte_array_hex + sizeof(byte_array_hex));
	sigscan_cleanup(newSignature);
	free(newSignature);

	printf("0xA9 has %zu hits\n", count);
	assert(count == 3);

	sigscan_cleanup(signature);
	free(signature);
}

const char* testStringSignatures(void* baseAddress)
{
	const char* string = "We are looking for this string in our .rodata";
	void* signature = malloc(sigscan_sizeof_string);
	sigscan_construct_string(signature, strdup(string));
	uintptr_t string2 = sigscan_next(signature, baseAddress);
	assert(string2 != NULL);
	printf("'%s' = '%s'\n", string, (const char*)string2);

	assert(string == string2); // Have we found the original?

	sigscan_cleanup(signature);
	free(signature);
	return string2;
}

void testXRefSignatures(void* baseAddress, const char* string)
{
	void* signature = malloc(sigscan_sizeof_xref);
	sigscan_construct_xref(signature, string, true, true);
	uintptr_t addr = sigscan_next(signature, baseAddress);
	assert(addr != NULL);

	Dl_info dlInfo;
	dladdr(addr, &dlInfo);
	printf("I found the string inside the following method: %s\n", dlInfo.dli_sname);
	assert(strcmp(dlInfo.dli_sname, "testStringSignatures") == 0);
	sigscan_cleanup(signature);
	free(signature);
}

int main()
{
	void* handle = dlopen(NULL, RTLD_GLOBAL | RTLD_NOW);
	struct link_map* linkMap;
	dlinfo(handle, RTLD_DI_LINKMAP, &linkMap);
	void* baseAddress = linkMap->l_addr;
	dlclose(handle);

	testByteSignatures();
	const char* addr = testStringSignatures(baseAddress);
	testXRefSignatures(baseAddress, addr);

	return 0;
}
