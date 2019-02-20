#include "logfile.h"
#include <stdarg.h>
#include <ntstrsafe.h>

#define MIN_LOG_BUFFER_SIZE (4 * 1024)
#define MIN_REMAINING 512
#define TAG '1gaT'

#define LOG_FILE L"inspect.log"

#define WRITE_TO_FILE 1

#if WRITE_TO_FILE
  typedef struct {
    HANDLE hFile;

    char* buf;
    SIZE_T bufsize;
    SIZE_T used;
  } logfile_t;

  static logfile_t logfile;
#endif /* WRITE_TO_FILE */

NTSTATUS OpenLogFile(SIZE_T log_buffer_size)
{
#if WRITE_TO_FILE
  UNICODE_STRING name;
  OBJECT_ATTRIBUTES attr;
  IO_STATUS_BLOCK io_status_block;
  NTSTATUS status;

  if (log_buffer_size < MIN_LOG_BUFFER_SIZE) {
    log_buffer_size = MIN_LOG_BUFFER_SIZE;
  }

  if ((logfile.buf = (char*) ExAllocatePoolWithTag(NonPagedPool,
                                                   log_buffer_size,
                                                   TAG)) == NULL) {
    return STATUS_NO_MEMORY;
  }

  RtlInitUnicodeString(&name, L"\\DosDevices\\C:\\" LOG_FILE);

  InitializeObjectAttributes(&attr,
                             &name,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                             NULL,
                             NULL);

  status = ZwCreateFile(&logfile.hFile,
                        SYNCHRONIZE | FILE_APPEND_DATA,
                        &attr,
                        &io_status_block,
                        NULL,
                        FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ,
                        FILE_OPEN_IF,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                        NULL,
                        0);

  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(logfile.buf, TAG);
    logfile.buf = NULL;

    return status;
  }

  logfile.bufsize = log_buffer_size;
  logfile.used = 0;
#else
  UNREFERENCED_PARAMETER(log_buffer_size);
#endif

  return STATUS_SUCCESS;
}

void CloseLogFile()
{
#if WRITE_TO_FILE
  if (logfile.buf) {
    if (logfile.hFile) {
      FlushLog();

      ZwClose(logfile.hFile);
      logfile.hFile = NULL;
    }

    ExFreePoolWithTag(logfile.buf, TAG);
    logfile.buf = NULL;
  }
#endif /* WRITE_TO_FILE */
}

BOOL Log(LARGE_INTEGER* system_time, const char* format, ...)
{
#if WRITE_TO_FILE
  va_list args;
  LARGE_INTEGER local_time;
  TIME_FIELDS time_fields;
  char* begin;
  char* end;
  SIZE_T remaining;

  remaining = logfile.bufsize - logfile.used;

  if (remaining < MIN_REMAINING) {
    if (!FlushLog()) {
      return FALSE;
    }

    remaining = logfile.bufsize;
  }

  ExSystemTimeToLocalTime(system_time, &local_time);
  RtlTimeToTimeFields(&local_time, &time_fields);

  begin = logfile.buf + logfile.used;

  RtlStringCbPrintfExA(begin,
                       remaining,
                       NULL,
                       NULL,
                       0,
                       "[%04u/%02u/%02u %02u:%02u:%02u.%03u] ",
                       time_fields.Year,
                       time_fields.Month,
                       time_fields.Day,
                       time_fields.Hour,
                       time_fields.Minute,
                       time_fields.Second,
                       time_fields.Milliseconds);

  begin += 26;
  remaining -= 26;

  va_start(args, format);

  switch (RtlStringCbVPrintfExA(begin,
                                remaining,
                                &end,
                                NULL,
                                0,
                                format,
                                args)) {
    case STATUS_SUCCESS:
      break;
    case STATUS_BUFFER_OVERFLOW:
      end = logfile.buf + logfile.bufsize - 1;
      *end = 0;
      *(end - 1) = '\n';
      *(end - 2) = '\r';
      *(end - 3) = '.';
      *(end - 4) = '.';
      *(end - 5) = '.';

      break;
    default:
      va_end(args);
      return FALSE;
  }

  va_end(args);

  logfile.used += (26 + (end - begin));

  return TRUE;
#else
  va_list args;
  char buf[1024];

  UNREFERENCED_PARAMETER(system_time);

  va_start(args, format);

  if (!NT_SUCCESS(RtlStringCbVPrintfExA(buf,
                                        sizeof(buf),
                                        NULL,
                                        NULL,
                                        STRSAFE_NO_TRUNCATION,
                                        format,
                                        args))) {
    va_end(args);
    return FALSE;
  }

  va_end(args);

  DbgPrint("%s", buf);

  return TRUE;
#endif
}

BOOL FlushLog()
{
#if WRITE_TO_FILE
  IO_STATUS_BLOCK io_status_block;
  NTSTATUS status;

  /* If the buffer is empty... */
  if (logfile.used == 0) {
    return TRUE;
  }

  status = ZwWriteFile(logfile.hFile,
                       NULL,
                       NULL,
                       NULL,
                       &io_status_block,
                       logfile.buf,
                       logfile.used,
                       NULL,
                       NULL);

  logfile.used = 0;

  return (status == STATUS_SUCCESS);
#else
  return TRUE;
#endif
}
