#ifndef LOGFILE_H
#define LOGFILE_H

#pragma warning(push)
#pragma warning(disable:4201) /* Unnamed struct/union. */

#include <fwpsk.h>

#pragma warning(pop)

NTSTATUS OpenLogFile(SIZE_T log_buffer_size);
void CloseLogFile();

BOOL Log(LARGE_INTEGER* system_time, const char* format, ...);
BOOL FlushLog();

#endif /* LOGFILE_H */
