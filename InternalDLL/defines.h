#define _YY_INTERNAL_STRINGIFY(NAME) #NAME
#define YY_STRINGIFY(NAME) _YY_INTERNAL_STRINGIFY(NAME)
#define YY_ARRAYSIZE(ARRAY) (sizeof(ARRAY) / sizeof(ARRAY[0]))
#define YY_ISINVALIDPTR(ptr) \
    ((ptr) == nullptr || \
     (ptr) == reinterpret_cast<void*>(0xCDCDCDCD) || \
     (ptr) == reinterpret_cast<void*>(0xDEADBEEF) || \
     (ptr) == reinterpret_cast<void*>(0xFEEEFEEE))
#define SERVER_HOST "toolbox.x64dbg.ru"
#define SERVER_PORT 80