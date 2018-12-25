#include <stdio.h>
#include "buf.h"

/* Note that multiple inclusion of this header is allowed. This lead to the
 * ability to set DEBUG per c file */

#define SHOW_FILE 1
#define SHOW_FILE 1

#define LOG_LEVEL_ERR	1
#define LOG_LEVEL_WARN	2
#define LOG_LEVEL_INFO	3
#define LOG_LEVEL_DEBUG 4

#ifdef DEBUG

// #define _LOG_MSG(level, format, ... ) \
//	do { \
//		struct timespec log_time; \
//		clock_gettime(CLOCK_REALTIME, &log_time); \
//		fprintf(stderr, "%s %lu %ld %s(%d) " format, \
//				level, \
//				log_time.tv_sec, log_time.tv_nsec, \
//				__FUNCTION__,  __LINE__, \
//				##__VA_ARGS__ ); \
//	} while (0);

 #if SHOW_FILE
  #define _LOG_MSG(level, format, ... ) \
 	do { \
 		fprintf(stderr, "%s %s:%d (%s) " format, \
 				level, \
 				__FILE__,  __LINE__, __FUNCTION__, \
 				##__VA_ARGS__ ); \
 	} while (0);
 #else
  #define _LOG_MSG(level, format, ... ) \
 	do { \
 		fprintf(stderr, "%s " format, \
 				level, \
 				##__VA_ARGS__ ); \
 	} while (0);
 #endif
 
 #if (DEBUG >= LOG_LEVEL_DEBUG)
  #define LOG_DEBUG(format, ... ) \
 	_LOG_MSG("DD", format, ##__VA_ARGS__ )
 #else
  #define LOG_DEBUG(format, ... )
 #endif
 
 
 #if (DEBUG >= LOG_LEVEL_INFO)
  #define LOG_INFO(format, ... ) \
 	_LOG_MSG("II", format, ##__VA_ARGS__ )
 #else
  #define LOG_INFO(format, ... )
 #endif
 
 
 #if (DEBUG >= LOG_LEVEL_WARN)
  #define LOG_WARN(format, ... ) \
 	_LOG_MSG("WW", format, ##__VA_ARGS__ )
 #else
  #define LOG_WARN(format, ... )
 #endif
 
 
 #if (DEBUG >= LOG_LEVEL_ERR)
  #define LOG_ERR(format, ... ) \
 	_LOG_MSG("EE", format, ##__VA_ARGS__ )
 #else
  #define LOG_ERR(format, ... )
 #endif
 
 #if (DEBUG >= LOG_LEVEL_DEBUG)
  #define LOG_HEXDUMP(buf, len) hexdump(buf, len)
  #define LOG_HEXDUMP_BUF(buf) buf_hexdump(buf)
 #else
  #define LOG_HEXDUMP(buf, len)
  #define LOG_HEXDUMP_BUF(buf)
 #endif

#else

 #define LOG_DEBUG(format, ... )
 #define LOG_INFO(format, ... )
 #define LOG_WARN(format, ... )
 #define LOG_ERR(format, ... )
 
 #define LOG_HEXDUMP(buf, len)
 #define LOG_HEXDUMP_BUF(buf)

#endif /* ifdef DEBUG */
