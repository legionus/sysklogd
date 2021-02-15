#ifndef SYSKLOGD_ATTRIBUTE_H_
#define SYSKLOGD_ATTRIBUTE_H_

#include "config.h"

#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
#define SYSKLOGD_FORMAT(params) __attribute__((__format__ params))
#else
#define SYSKLOGD_FORMAT(params)
#endif

#ifdef HAVE_FUNC_ATTRIBUTE_NONNULL
#define SYSKLOGD_NONNULL(params) __attribute__((__nonnull__ params))
#else
#define SYSKLOGD_NONNULL(params)
#endif

#ifdef HAVE_FUNC_ATTRIBUTE_NONNULL
#define SYSKLOGD_NORETURN() __attribute__((__noreturn__))
#else
#define SYSKLOGD_NORETURN()
#endif

#ifdef HAVE_FUNC_ATTRIBUTE_UNUSED
#define SYSKLOGD_UNUSED(x) x __attribute__((__unused__))
#else
#define SYSKLOGD_UNUSED(x) x
#endif

#ifdef HAVE_FUNC_ATTRIBUTE_PURE
#define SYSKLOGD_PURE() __attribute__((__pure__))
#else
#define SYSKLOGD_PURE()
#endif

#endif /* SYSKLOGD_ATTRIBUTE_H_ */
