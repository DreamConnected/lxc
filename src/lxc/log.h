/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_LOG_H
#define __LXC_LOG_H

#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <syslog.h>
#include <time.h>

#include "compiler.h"
#include "conf.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif

#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC 1030
#endif

#define LXC_LOG_PREFIX_SIZE 32
#define LXC_LOG_BUFFER_SIZE 4096

#ifndef LXC_LOG_TAG
#define LXC_LOG_TAG "lxc"
#endif

#ifdef USE_ANDROID_LOG
#include <android/log.h>
#endif

/* predefined lxc log priorities. */
enum lxc_loglevel {
	LXC_LOG_LEVEL_TRACE,
	LXC_LOG_LEVEL_DEBUG,
	LXC_LOG_LEVEL_INFO,
	LXC_LOG_LEVEL_NOTICE,
	LXC_LOG_LEVEL_WARN,
	LXC_LOG_LEVEL_ERROR,
	LXC_LOG_LEVEL_CRIT,
	LXC_LOG_LEVEL_ALERT,
	LXC_LOG_LEVEL_FATAL,
	LXC_LOG_LEVEL_NOTSET,
};

/* location information of the logging event */
struct lxc_log_locinfo {
	const char *file;
	const char *func;
	int line;
};

#define LXC_LOG_LOCINFO_INIT						\
	{ .file = __FILE__, .func = __func__, .line = __LINE__	}

/* brief logging event object */
struct lxc_log_event {
	const char *category;
	int priority;
	struct timespec timestamp;
	struct lxc_log_locinfo *locinfo;
	const char *fmt;
	va_list *vap;
};

/* log appender object */
struct lxc_log_appender {
	const char *name;
	int (*append)(const struct lxc_log_appender *, struct lxc_log_event *);

	/*
	 * appenders can be stacked
	 */
	struct lxc_log_appender *next;
};

/* log category object */
struct lxc_log_category {
	const char *name;
	int priority;
	struct lxc_log_appender *appender;
	const struct lxc_log_category *parent;
};

#ifndef NO_LXC_CONF
extern bool lxc_log_use_global_fd;
#endif

/*
 * Returns true if the chained priority is equal to or higher than
 * given priority.
 */
static inline int lxc_log_priority_is_enabled(const struct lxc_log_category *category,
					      int priority)
{
	while (category->priority == LXC_LOG_LEVEL_NOTSET && category->parent)
		category = category->parent;

	int cmp_prio = category->priority;
#ifndef NO_LXC_CONF
	if (!lxc_log_use_global_fd && current_config &&
	    current_config->loglevel != LXC_LOG_LEVEL_NOTSET)
		cmp_prio = current_config->loglevel;
#endif

	return priority >= cmp_prio;
}

/*
 * converts a priority to a literal string
 */
static inline const char *lxc_log_priority_to_string(int priority)
{
	switch (priority) {
	case LXC_LOG_LEVEL_TRACE:
		return "TRACE";
	case LXC_LOG_LEVEL_DEBUG:
		return "DEBUG";
	case LXC_LOG_LEVEL_INFO:
		return "INFO";
	case LXC_LOG_LEVEL_NOTICE:
		return "NOTICE";
	case LXC_LOG_LEVEL_WARN:
		return "WARN";
	case LXC_LOG_LEVEL_ERROR:
		return "ERROR";
	case LXC_LOG_LEVEL_CRIT:
		return "CRIT";
	case LXC_LOG_LEVEL_ALERT:
		return "ALERT";
	case LXC_LOG_LEVEL_FATAL:
		return "FATAL";
	}

	return "NOTSET";
}

static inline const char *lxc_syslog_priority_to_string(int priority)
{
	switch (priority) {
	case LOG_DAEMON:
		return "daemon";
	case LOG_LOCAL0:
		return "local0";
	case LOG_LOCAL1:
		return "local1";
	case LOG_LOCAL2:
		return "local2";
	case LOG_LOCAL3:
		return "local3";
	case LOG_LOCAL4:
		return "local4";
	case LOG_LOCAL5:
		return "local5";
	case LOG_LOCAL6:
		return "local6";
	case LOG_LOCAL7:
		return "local7";
	}

	return "NOTSET";
}

/*
 * converts a literal priority to an int
 */
static inline int lxc_log_priority_to_int(const char *name)
{
	if (strcasecmp("TRACE", name) == 0)
		return LXC_LOG_LEVEL_TRACE;
	if (strcasecmp("DEBUG", name) == 0)
		return LXC_LOG_LEVEL_DEBUG;
	if (strcasecmp("INFO", name) == 0)
		return LXC_LOG_LEVEL_INFO;
	if (strcasecmp("NOTICE", name) == 0)
		return LXC_LOG_LEVEL_NOTICE;
	if (strcasecmp("WARN", name) == 0)
		return LXC_LOG_LEVEL_WARN;
	if (strcasecmp("ERROR", name) == 0)
		return LXC_LOG_LEVEL_ERROR;
	if (strcasecmp("CRIT", name) == 0)
		return LXC_LOG_LEVEL_CRIT;
	if (strcasecmp("ALERT", name) == 0)
		return LXC_LOG_LEVEL_ALERT;
	if (strcasecmp("FATAL", name) == 0)
		return LXC_LOG_LEVEL_FATAL;

	return LXC_LOG_LEVEL_NOTSET;
}

static inline int lxc_syslog_priority_to_int(const char *name)
{
	if (strcasecmp("daemon", name) == 0)
		return LOG_DAEMON;
	if (strcasecmp("local0", name) == 0)
		return LOG_LOCAL0;
	if (strcasecmp("local1", name) == 0)
		return LOG_LOCAL1;
	if (strcasecmp("local2", name) == 0)
		return LOG_LOCAL2;
	if (strcasecmp("local3", name) == 0)
		return LOG_LOCAL3;
	if (strcasecmp("local4", name) == 0)
		return LOG_LOCAL4;
	if (strcasecmp("local5", name) == 0)
		return LOG_LOCAL5;
	if (strcasecmp("local6", name) == 0)
		return LOG_LOCAL6;
	if (strcasecmp("local7", name) == 0)
		return LOG_LOCAL7;

	return -EINVAL;
}

static inline void __lxc_log_append(const struct lxc_log_appender *appender,
				    struct lxc_log_event *event)
{
	va_list va;
	va_list *va_keep = event->vap;

	while (appender) {
		va_copy(va, *va_keep);
		event->vap = &va;
		appender->append(appender, event);
		appender = appender->next;
		va_end(va);
	}
}

static inline void __lxc_log(const struct lxc_log_category *category,
			     struct lxc_log_event *event)
{
	while (category) {
		__lxc_log_append(category->appender, event);
		category = category->parent;
	}
}

/*
 * Helper macro to define log functions.
 */
#define lxc_log_priority_define(acategory, LEVEL)				\
										\
__lxc_unused __attribute__ ((format (printf, 2, 3)))				\
static inline void LXC_##LEVEL(struct lxc_log_locinfo *, const char *, ...);	\
										\
__lxc_unused static inline void LXC_##LEVEL(struct lxc_log_locinfo* locinfo,	\
					   const char* format, ...)		\
{										\
	if (lxc_log_priority_is_enabled(acategory, LXC_LOG_LEVEL_##LEVEL)) {	\
		va_list va_ref;							\
		int saved_errno;						\
		struct lxc_log_event evt = {					\
			.category	= (acategory)->name,			\
			.priority	= LXC_LOG_LEVEL_##LEVEL,		\
			.fmt		= format,				\
			.locinfo	= locinfo				\
		};								\
										\
		/* clock_gettime() is explicitly marked as MT-Safe		\
		 * without restrictions. So let's use it for our		\
		 * logging stamps.						\
		 */								\
		saved_errno = errno;						\
		(void)clock_gettime(CLOCK_REALTIME, &evt.timestamp);		\
										\
		va_start(va_ref, format);					\
		evt.vap = &va_ref;						\
		__lxc_log(acategory, &evt);					\
		va_end(va_ref);							\
		errno = saved_errno;						\
	}									\
}

/*
 * Helper macro to define and use static categories.
 */
#define lxc_log_category_define(name, parent)					\
	extern struct lxc_log_category lxc_log_category_##parent;	\
	struct lxc_log_category lxc_log_category_##name = {		\
		#name,								\
		LXC_LOG_LEVEL_NOTSET,						\
		NULL,								\
		&lxc_log_category_##parent					\
	};

#define lxc_log_define(name, parent)					\
	lxc_log_category_define(name, parent)				\
									\
	lxc_log_priority_define(&lxc_log_category_##name, TRACE)	\
	lxc_log_priority_define(&lxc_log_category_##name, DEBUG)	\
	lxc_log_priority_define(&lxc_log_category_##name, INFO)		\
	lxc_log_priority_define(&lxc_log_category_##name, NOTICE)	\
	lxc_log_priority_define(&lxc_log_category_##name, WARN)		\
	lxc_log_priority_define(&lxc_log_category_##name, ERROR)	\
	lxc_log_priority_define(&lxc_log_category_##name, CRIT)		\
	lxc_log_priority_define(&lxc_log_category_##name, ALERT)	\
	lxc_log_priority_define(&lxc_log_category_##name, FATAL)

#define lxc_log_category_priority(name) 				\
	(lxc_log_priority_to_string(lxc_log_category_##name.priority))

/*
 * Helper macro to define errno string.
 */
#if HAVE_STRERROR_R
	#if STRERROR_R_CHAR_P
	char *strerror_r(int errnum, char *buf, size_t buflen);
	#else
	int strerror_r(int errnum, char *buf, size_t buflen);
	#endif

	#if STRERROR_R_CHAR_P
		#define lxc_log_strerror_r                                               \
			char errno_buf[PATH_MAX / 2] = {"Failed to get errno string"};   \
			char *ptr = NULL;                                                \
			{                                                                \
				int __saved_errno = errno;				 \
				ptr = strerror_r(errno, errno_buf, sizeof(errno_buf));   \
				errno = __saved_errno;					 \
				if (!ptr)                                                \
					ptr = errno_buf;                                 \
			}
	#else
		#define lxc_log_strerror_r                                               \
			char errno_buf[PATH_MAX / 2] = {"Failed to get errno string"};   \
			char *ptr = errno_buf;                                           \
			{                                                                \
				int __saved_errno = errno;				 \
				(void)strerror_r(errno, errno_buf, sizeof(errno_buf));   \
				errno = __saved_errno;					 \
			}
	#endif
#elif ENFORCE_THREAD_SAFETY
	#error ENFORCE_THREAD_SAFETY was set but cannot be guaranteed
#else
	#define lxc_log_strerror_r							 \
		char *ptr = NULL;              						 \
		{                              						 \
			ptr = strerror(errno); 						 \
		}
#endif

/*
 * top categories
 */
#define TRACE(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_TRACE(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define DEBUG(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_DEBUG(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define INFO(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_INFO(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define NOTICE(format, ...) do {					\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_NOTICE(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define WARN(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_WARN(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define ERROR(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_ERROR(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define CRIT(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_CRIT(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define ALERT(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_ALERT(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define FATAL(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_FATAL(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#if (defined(__GNU_LIBRARY__) || defined(__MUSL__))  && !ENABLE_COVERITY_BUILD
#define SYSTRACE(format, ...)                              \
		TRACE("%m - " format, ##__VA_ARGS__)
#elif IS_BIONIC && USE_ANDROID_LOG
#define SYSTRACE(format, ...)                              \
                __android_log_print(ANDROID_LOG_VERBOSE, LXC_LOG_TAG, format, ##__VA_ARGS__)
#else
#define SYSTRACE(format, ...)                              \
	do {                                               \
		lxc_log_strerror_r;                        \
		TRACE("%s - " format, ptr, ##__VA_ARGS__); \
	} while (0)
#endif

#if (defined(__GNU_LIBRARY__) || defined(__MUSL__))  && !ENABLE_COVERITY_BUILD
#define SYSDEBUG(format, ...)                              \
                DEBUG("%m - " format, ##__VA_ARGS__)
#elif IS_BIONIC && USE_ANDROID_LOG
#define SYSDEBUG(format, ...)                              \
                __android_log_print(ANDROID_LOG_DEBUG, LXC_LOG_TAG, format, ##__VA_ARGS__)
#else
#define SYSDEBUG(format, ...)                              \
	do {                                               \
		lxc_log_strerror_r;                        \
		DEBUG("%s - " format, ptr, ##__VA_ARGS__); \
	} while (0)
#endif


#if (defined(__GNU_LIBRARY__) || defined(__MUSL__))  && !ENABLE_COVERITY_BUILD
#define SYSINFO(format, ...)                              \
                INFO("%m - " format, ##__VA_ARGS__)
#elif IS_BIONIC && USE_ANDROID_LOG
#define SYSINFO(format, ...)                              \
                __android_log_print(ANDROID_LOG_INFO, LXC_LOG_TAG, format, ##__VA_ARGS__)
#else
#define SYSINFO(format, ...)                              \
	do {                                              \
		lxc_log_strerror_r;                       \
		INFO("%s - " format, ptr, ##__VA_ARGS__); \
	} while (0)
#endif

#if (defined(__GNU_LIBRARY__) || defined(__MUSL__))  && !ENABLE_COVERITY_BUILD
#define SYSNOTICE(format, ...)                              \
		NOTICE("%m - " format, ##__VA_ARGS__)
#elif IS_BIONIC && USE_ANDROID_LOG
#define SYSNOTICE(format, ...)                              \
                __android_log_print(ANDROID_LOG_INFO, LXC_LOG_TAG, format, ##__VA_ARGS__)
#else
#define SYSNOTICE(format, ...)                              \
	do {                                                \
		lxc_log_strerror_r;                         \
		NOTICE("%s - " format, ptr, ##__VA_ARGS__); \
	} while (0)
#endif

#if (defined(__GNU_LIBRARY__) || defined(__MUSL__))  && !ENABLE_COVERITY_BUILD
#define SYSWARN(format, ...)                              \
		WARN("%m - " format, ##__VA_ARGS__)
#elif IS_BIONIC && USE_ANDROID_LOG
#define SYSWARN(format, ...)                              \
                __android_log_print(ANDROID_LOG_WARN, LXC_LOG_TAG, format, ##__VA_ARGS__)
#else
#define SYSWARN(format, ...)                              \
	do {                                              \
		lxc_log_strerror_r;                       \
		WARN("%s - " format, ptr, ##__VA_ARGS__); \
	} while (0)
#endif

#if (defined(__GNU_LIBRARY__) || defined(__MUSL__))  && !ENABLE_COVERITY_BUILD
#define SYSERROR(format, ...)                              \
		ERROR("%m - " format, ##__VA_ARGS__)
#elif IS_BIONIC && USE_ANDROID_LOG
#define SYSERROR(format, ...)                              \
                __android_log_print(ANDROID_LOG_ERROR, LXC_LOG_TAG, format, ##__VA_ARGS__)
#else
#define SYSERROR(format, ...)                              \
	do {                                               \
		lxc_log_strerror_r;                        \
		ERROR("%s - " format, ptr, ##__VA_ARGS__); \
	} while (0)
#endif

#if (defined(__GNU_LIBRARY__) || defined(__MUSL__))  && !ENABLE_COVERITY_BUILD
#define CMD_SYSERROR(format, ...)                                             \
	fprintf(stderr, "%s: %d: %s - %m - " format "\n", __FILE__, __LINE__, \
		__func__, ##__VA_ARGS__);
#else
#define CMD_SYSERROR(format, ...)                                           \
	do {                                                                \
		lxc_log_strerror_r;                                         \
		fprintf(stderr, "%s: %d: %s - %s - " format "\n", __FILE__, \
			__LINE__, __func__, ptr, ##__VA_ARGS__);            \
	} while (0)
#endif

#if (defined(__GNU_LIBRARY__) || defined(__MUSL__))  && !ENABLE_COVERITY_BUILD
#define CMD_SYSINFO(format, ...)                                               \
	printf("%s: %d: %s - %m - " format "\n", __FILE__, __LINE__, __func__, \
	       ##__VA_ARGS__);
#else
#define CMD_SYSINFO(format, ...)                                             \
	do {                                                                 \
		lxc_log_strerror_r;                                          \
		printf("%s: %d: %s - %s - " format "\n", __FILE__, __LINE__, \
		       __func__, ptr, ##__VA_ARGS__);                        \
	} while (0)
#endif

#define log_error_errno(__ret__, __errno__, format, ...)      \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		errno = (__errno__);                          \
		SYSERROR(format, ##__VA_ARGS__);              \
		__internal_ret__;                             \
	})

#define log_error(__ret__, format, ...)                       \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		ERROR(format, ##__VA_ARGS__);                 \
		__internal_ret__;                             \
	})

#define log_trace_errno(__ret__, __errno__, format, ...)      \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		errno = __errno__;                            \
		SYSTRACE(format, ##__VA_ARGS__);              \
		__internal_ret__;                             \
	})

#define log_trace(__ret__, format, ...)                       \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		TRACE(format, ##__VA_ARGS__);                 \
		__internal_ret__;                             \
	})

#define log_warn_errno(__ret__, __errno__, format, ...)       \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		errno = __errno__;                            \
		SYSWARN(format, ##__VA_ARGS__);               \
		__internal_ret__;                             \
	})

#define log_warn(__ret__, format, ...)                        \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		WARN(format, ##__VA_ARGS__);                  \
		__internal_ret__;                             \
	})

#define log_debug_errno(__ret__, __errno__, format, ...)      \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		errno = __errno__;                            \
		SYSDEBUG(format, ##__VA_ARGS__);              \
		__internal_ret__;                             \
	})

#define log_debug(__ret__, format, ...)                       \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		DEBUG(format, ##__VA_ARGS__);                 \
		__internal_ret__;                             \
	})

#define log_info_errno(__ret__, __errno__, format, ...)       \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		errno = __errno__;                            \
		SYSINFO(format, ##__VA_ARGS__);               \
		__internal_ret__;                             \
	})

#define log_info(__ret__, format, ...)                        \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		INFO(format, ##__VA_ARGS__);                  \
		__internal_ret__;                             \
	})

/* These are the logging return helpers to be used. */
#define syserror(format, ...)                    \
	({                                       \
		SYSERROR(format, ##__VA_ARGS__); \
		(-labs(errno));                  \
	})

#define syserror_set(__ret__, format, ...)                    \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		errno = labs(__ret__);                        \
		SYSERROR(format, ##__VA_ARGS__);              \
		__internal_ret__;                             \
	})

#define syserror_ret(__ret__, format, ...)                    \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		SYSERROR(format, ##__VA_ARGS__);              \
		__internal_ret__;                             \
	})

#define error_ret(__ret__, format, ...)                       \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		ERROR(format, ##__VA_ARGS__);                 \
		__internal_ret__;                             \
	})

#define syswarn(format, ...)                    \
	({                                      \
		SYSWARN(format, ##__VA_ARGS__); \
		(-labs(errno));                 \
	})

#define syswarn_set(__ret__, format, ...)                     \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		errno = labs(__ret__);                        \
		SYSWARN(format, ##__VA_ARGS__);               \
		__internal_ret__;                             \
	})

#define syswarn_ret(__ret__, format, ...)                     \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		SYSWARN(format, ##__VA_ARGS__);               \
		__internal_ret__;                             \
	})

#define sysinfo(format, ...)                    \
	({                                      \
		SYSINFO(format, ##__VA_ARGS__); \
		(-labs(errno));                 \
	})

#define sysinfo_set(__ret__, format, ...)                     \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		errno = labs(__ret__);                        \
		SYSINFO(format, ##__VA_ARGS__);               \
		__internal_ret__;                             \
	})

#define sysinfo_ret(__ret__, format, ...)                    \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		SYSINFO(format, ##__VA_ARGS__);              \
		__internal_ret__;                             \
	})

#define sysdebug(format, ...)                    \
	({                                       \
		SYSDEBUG(format, ##__VA_ARGS__); \
		(-labs(errno));                  \
	})

#define sysdebug_set(__ret__, format, ...)                    \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		errno = labs(__ret__);                        \
		SYSDEBUG(format, ##__VA_ARGS__);              \
		__internal_ret__;                             \
	})

#define sysdebug_ret(__ret__, format, ...)                    \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		SYSDEBUG(format, ##__VA_ARGS__);              \
		__internal_ret__;                             \
	})

#define systrace(format, ...)                    \
	({                                       \
		SYSTRACE(format, ##__VA_ARGS__); \
		(-labs(errno));                  \
	})

#define systrace_set(__ret__, format, ...)                    \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		errno = labs(__ret__);                        \
		SYSTRACE(format, ##__VA_ARGS__);              \
		__internal_ret__;                             \
	})

#define systrace_ret(__ret__, format, ...)                    \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		SYSTRACE(format, ##__VA_ARGS__);              \
		__internal_ret__;                             \
	})

extern int lxc_log_fd;

__hidden extern int lxc_log_syslog(int facility);
__hidden extern void lxc_log_syslog_enable(void);
__hidden extern void lxc_log_syslog_disable(void);
__hidden extern int lxc_log_set_level(int *dest, int level);
__hidden extern int lxc_log_get_level(void);
static inline bool lxc_log_trace(void)
{
	return lxc_log_get_level() <= LXC_LOG_LEVEL_TRACE;
}
__hidden extern bool lxc_log_has_valid_level(void);
__hidden extern int lxc_log_set_file(int *fd, const char *fname);
__hidden extern const char *lxc_log_get_file(void);
__hidden extern void lxc_log_set_prefix(const char *prefix);
__hidden extern const char *lxc_log_get_prefix(void);
__hidden extern void lxc_log_options_no_override(void);
__hidden extern int lxc_log_get_fd(void);

#endif /* __LXC_LOG_H */
