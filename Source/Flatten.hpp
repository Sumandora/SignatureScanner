#ifdef __GNUC__
#define FLATTEN __attribute((flatten))
#else
#define FLATTEN [[gnu::flatten]]
#endif
