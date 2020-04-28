#include <stdbool.h>

typedef struct PptSync PptSync;

/* Initializes the synchronizer.
 * 
 * If an error occurs, it is printed to standard error and this function returns NULL.
 * 
 * `ppt-sync.exe` must exist in the working directory of your program.
 */
PptSync *pptsync_new();

/* Waits until PPT reaches the next frame.
 * 
 * PPT will be blocked until the next call to this function, so do not do blocking operations
 * or expensive computation between calls to this function.
 * 
 * This function returns false if it can't communicate with the synchronizer. This usually happens
 * when PPT closes. Once this function returns false, you should destroy the synchronizer.
 */
bool pptsync_wait_for_frame(PptSync *pptsync);

/* Cleanup the synchronizer. */
void pptsync_destroy(PptSync *pptsync);