#include <stdio.h>

/* Note that multiple inclusion of this header is allowed. This lead to the
 * ability to set DEBUG per c file */

#ifdef DEBUG

#define _LOG_MSG(level, format, ... ) \
	fprintf(stderr, "%s %s(%d) " format, level, __FUNCTION__,  __LINE__, __VA_ARGS__ )

#define LOG_ERR(format, ... ) \
	_LOG_MSG("EE", format, __VA_ARGS__ )

#define LOG_WARN(format, ... ) \
	_LOG_MSG("WW", format, __VA_ARGS__ )

#define LOG_INFO(format, ... ) \
	_LOG_MSG("II", format, __VA_ARGS__ )

#else

#define LOG_ERR(format, ... )
#define LOG_WARN(format, ... )
#define LOG_INFO(format, ... )

#endif

