#include <stdio.h>

/* Note that multiple inclusion of this header is allowed. This lead to the
 * ability to set DEBUG per c file */

#define LOG_LEVEL_ERR	1
#define LOG_LEVEL_WARN	2
#define LOG_LEVEL_INFO	3
#define LOG_LEVEL_DEBUG 4

#ifdef DEBUG


#define _LOG_MSG(level, format, ... ) \
	fprintf(stderr, "%s %s(%d) " format, level, __FUNCTION__,  __LINE__ \
			__VA_OPT__(,) __VA_ARGS__ )

#if (DEBUG >= LOG_LEVEL_DEBUG)
#define LOG_DEBUG(format, ... ) \
	_LOG_MSG("DD", format, __VA_ARGS__ )
#else
#define LOG_DEBUG(format, ... )
#endif


#if (DEBUG >= LOG_LEVEL_INFO)
#define LOG_INFO(format, ... ) \
	_LOG_MSG("II", format, __VA_ARGS__ )
#else
#define LOG_INFO(format, ... )
#endif


#if (DEBUG >= LOG_LEVEL_WARN)
#define LOG_WARN(format, ... ) \
	_LOG_MSG("II", format, __VA_ARGS__ )
#else
#define LOG_WARN(format, ... )
#endif


#if (DEBUG >= LOG_LEVEL_ERR)
#define LOG_ERR(format, ... ) \
	_LOG_MSG("II", format, __VA_ARGS__ )
#else
#define LOG_ERR(format, ... )
#endif

#else

#define LOG_DEBUG(format, ... )
#define LOG_INFO(format, ... )
#define LOG_WARN(format, ... )
#define LOG_ERR(format, ... )

#endif /* ifdef DEBUG */

