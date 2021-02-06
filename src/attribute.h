#ifndef SYSKLOGD_ATTRIBUTE_H_
#define SYSKLOGD_ATTRIBUTE_H_

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define SYSKLOGD_GNUC_PREREQ(maj, min) \
	((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#define SYSKLOGD_GNUC_PREREQ(maj, min) 0
#endif

#if SYSKLOGD_GNUC_PREREQ(2, 5)
#define SYSKLOGD_FORMAT(params) __attribute__((__format__ params))
#define SYSKLOGD_NORETURN() __attribute__((__noreturn__))
#else
#define SYSKLOGD_FORMAT(params)
#define SYSKLOGD_NORETURN()
#endif

#if SYSKLOGD_GNUC_PREREQ(3, 3)
#define SYSKLOGD_NONNULL(params) __attribute__((__nonnull__ params))
#else
#define SYSKLOGD_NONNULL(params)
#endif

#endif /* SYSKLOGD_ATTRIBUTE_H_ */
