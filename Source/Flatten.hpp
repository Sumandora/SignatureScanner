#ifdef __GNUC__
#define FLATTEN __attribute((flatten))
#elif __clang__
#define FLATTEN [[gnu::flatten]]
#else
#define FLATTEN
#endif
