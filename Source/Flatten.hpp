#ifdef __GNUC__
#define FLATTEN __attribute((flatten))
#elif __clang__
#define FLATTEN [[gnu::flatten]]
#else
#warning Your compiler does not support the [[gnu::flatten]] attribute, performance of SignatureScanner may be impacted
#define FLATTEN
#endif
