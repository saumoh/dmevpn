#define EV_STANDALONE 1
#define EV_MULTIPLICITY 0
#define EV_VERIFY 0

#define EV_USE_CLOCK_SYSCALL 1
#define EV_USE_SELECT 0
#define EV_USE_POLL 1

#define EV_IDLE_ENABLE 1

/* Unused stuff, disabled for size optimization */
#define EV_USE_INOTIFY 0
#define EV_PERIODIC_ENABLE 0
#define EV_EMBED_ENABLE 0
#define EV_STAT_ENABLE 0
#define EV_FORK_ENABLE 0
#define EV_ASYNC_ENABLE 0

/* Disable the "void *data;" member of watchers to save memory */
#define EV_COMMON /* empty */

#include "../libev/ev.h"
