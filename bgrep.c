/* Grep binary signatures
 * Forked by mozkito <three1518@163.com>
 *
 * Copyright 2009 Felix Domke <tmbinc@elitedvb.net>. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *    this list of
 *       conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list
 *       of conditions and the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the copyright holder. */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef char i8;
typedef short i16;
typedef int i32;
typedef long long i64;

#define BGREP_VERSION "0.3"
#define PBLOCK_SIZE 512
#define VBLOCK_SIZE 4096
#define VMEM_BEGIN 0ULL
#define VMEM_END ((1ULL << 63) - 1)

#ifdef _WIN32

#include <Windows.h>

#else

#define __USE_FILE_OFFSET64 // enable lseek64

#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#endif

// universal io object, including an id number and 3 pointers
typedef struct ioobj {

#ifdef _WIN32
  HANDLE id;
#else
  int id;
#endif

  u64 begin;
  u64 end;
  u64 curr;
} ioobj;

u8 flag_process;
u8 flag_reverse;
u8 flag_verbose;
u8 flag_quick;

u32 limit; // max number of search results
char *limit_str;

typedef struct option {
  char *str;
  char *abbr;
  u8 *flag;
  char **param;
} option;

option opts[] = {{"process", "p", &flag_process, NULL},
                 {"reverse", "r", &flag_reverse, NULL},
                 {"verbose", "v", &flag_verbose, NULL},
                 {"limit", "l", &flag_quick, &limit_str},
                 {NULL, NULL, NULL, NULL}};

void usage() {
  fprintf(stderr, "bgrep version: %s\n", BGREP_VERSION);
  fprintf(stderr, "usage: bgrep -[prv] [-l count] <hex> <target>\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -p, --process: <target> is pid instead of file path\n");
  fprintf(stderr, "  -r, --reverse: reversed search\n");
  fprintf(stderr, "  -v, --verbose: show both address and binary\n");
  fprintf(stderr, "  -l, --limit [count]: max number of results to show\n");
  exit(1);
}

void die(const char *msg, ...) {
  va_list ap;
  va_start(ap, msg);
  vfprintf(stderr, msg, ap);
  fprintf(stderr, "\n");
  va_end(ap);
  exit(1);
}

// abstract layer of opening, return null on error
ioobj *open_object(char *repr) {

#ifdef _WIN32

  if (flag_process) {
    ioobj *process = (ioobj *)malloc(sizeof(ioobj));

    // enable PROCESS_QUERY_INFORMATION for VirtualQueryEx
    process->id = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                              FALSE, atoi(repr));
    if (process->id == NULL) {
      return NULL;
    }

    // set io object to code section
    u64 pAddress = VMEM_BEGIN;
    MEMORY_BASIC_INFORMATION mbi;
    while (pAddress < VMEM_END) {

      memset(&mbi, 0, sizeof(mbi));
      if (!VirtualQueryEx(process->id, pAddress, &mbi, sizeof(mbi))) {
        return NULL;
      }

      /* iteration stops upon the first code section
       * normally, it's the .text section of main program
       * however sometimes it's not the case especially for some handmade PEs,
       * which requires further research */
      if (mbi.State == MEM_COMMIT && mbi.State == MEM_IMAGE &&
          (mbi.Protect == PAGE_EXECUTE_READ ||
           mbi.Protect == PAGE_EXECUTE_READWRITE)) {
        process->begin = process->curr = (u64)mbi.BaseAddress;
        process->end = process->begin + mbi.RegionSize;
        break;
      }

      // calculate the next possible
      pAddress = (u64)mbi.BaseAddress + mbi.RegionSize;
    }

    return process;

  } else {
    ioobj *file = (ioobj *)malloc(sizeof(ioobj));

    file->id = CreateFileA(repr, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file->id == INVALID_HANDLE_VALUE) {
      return -1;
    }

    // refuse to touch directories
    DWORD fileAttributes = GetFileAttributesA(repr);
    if (fileAttributes == INVALID_FILE_ATTRIBUTES ||
        (fileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
      return NULL;
    }

    // for files we set the search boundry to (0, size of file)
    LARGE_INTEGER fileSize;
    file->begin = file->curr = 0ULL;
    if (!GetFileSizeEx(file->id, &fileSize)) {
      return -1;
    }

    file->end = fileSize.QuadPart;
    return file;
  }

#else

  if (flag_process) {
    ioobj *process = (ioobj *)malloc(sizeof(ioobj));
    char buffer_path[32], buffer_value[40];

    /* for linux processes we can't get process information with APIs unless we
     * use ptrace to debug it
     * to get process's memory map we have to parse /proc/<pid>/maps */
    process->id = atoi(repr);
    sprintf(buffer_path, "/proc/%u/maps", process->id);
    FILE *fp = fopen(buffer_path, "r");
    if (fp == NULL) {
      return -1;
    }

    char c, r, w, x;
    u64 begin, end;

    while (fgets(buffer_value, 40, fp) != NULL) {

      // search process map and set io object to the first code section
      sscanf(buffer_value, "%llu-%llu %c%c%c", &begin, &end, &r, &w, &x);

      if (x != '-') {
        process->begin = process->curr = begin;
        process->end = end;
        break;
      }

      while ((c = getc(fp)) != EOF && c != '\n')
        ;
    }

    fclose(fp);
    return process;

  } else {
    ioobj *file = (ioobj *)malloc(sizeof(ioobj));

    file->id = open(repr, O_RDONLY);
    struct stat fst;
    if (fstat(file->id, &fst) == -1) {
      return -1;
    }

    // refuse to touch directories
    if (!S_ISREG(fst.st_mode) || S_ISDIR(fst.st_mode)) {
      return -1;
    }

    // for files we set the search boundry to (0, size of file)
    file->begin = file->curr = 0LL;
    file->end = fst.st_size;
    return file;
  }

#endif
}

// abstract layer of reading, return -1 on error
u32 read_object(ioobj *any, u8 *buffer, u32 size) {

#ifdef _WIN32

  DWORD bytesRead = 0;
  DWORD cb = any->curr + size > any->end ? any->end - any->curr : size;

  if (flag_process) {
    if (!ReadProcessMemory(any->id, any->curr, buffer, cb, &bytesRead)) {
      return -1;
    }
  } else {
    if (!ReadFile(any->id, buffer, cb, &bytesRead, NULL)) {
      return -1;
    }
  }

  /* we should never touch bytes outside the boundry.
   * our io pointer should always have the same value as file offset */
  any->curr += bytesRead;
  return bytesRead;

#else

  u32 ct = 0;
  u32 to_read = any->curr + size > any->end ? any->end - any->curr : size;

  if (flag_process) {

    struct iovec local = {.iov_base = buffer, .iov_len = size};
    struct iovec remote = {.iov_base = any->curr, .iov_len = to_read};

    ct = process_vm_readv(any->id, &local, 1, &remote, 1, 0);
    if (ct == -1) {
      return -1;
    }
  } else {
    ct = read(any->id, buffer, to_read);
    if (ct == -1) {
      return -1;
    }
  }

  /* we should never touch bytes outside the boundry.
   * our io pointer should always have the same value as file offset */
  any->curr += ct;
  return ct;

#endif
}

// abstract io layer of closing
void close_object(ioobj *any) {

  /* for windows, any process/file is associated with a handle; for linux it's
   * a file descriptor */
#ifdef _WIN32
  CloseHandle(any->id);
#else
  close(any->id);
#endif

  free(any);
}

// abstract io layer of seeking, return -1 on failure
u64 seek_object(ioobj *any, i64 offset) {
  i64 pos = 0;
  pos = offset >= 0 ? any->begin + offset : any->end + offset;

  /* we restrict target pointer in (any->begin, any->end)
   * negative offsets for seeking from the end */
  if (pos > any->end) {
    pos = any->end;
  } else if (pos < any->begin) {
    pos = any->begin;
  }

  if (flag_process) {
    // for processes, we just set the target pointer
    any->curr = pos;
  } else {

    /* we make our target pointer track the 64-bit file offset, for windows
     * it's SetFilePointerEx, for linux it's lseek64 (define
     * __USE_FILE_OFFSET64 before including unistd.h) */
#ifdef _WIN32
    LARGE_INTEGER position, newPosition;
    position.QuadPart = pos;
    if (!SetFilePointerEx(any->id, position, &newPosition, FILE_BEGIN)) {
      return -1;
    }
    any->curr = newPosition.QuadPart;
#else
    i64 curr = lseek64(any->id, pos, SEEK_SET);
    if (curr == -1) {
      return -1;
    }
    any->curr = curr;
#endif
  }

  return any->curr;
}

// 8-byte group matching, if there's a match, return 1
u8 match(u8 *buffer, u64 vbase, i32 i, u8 *pattern, u8 *mask, i32 len) {

  i32 j = 0;
  while (j <= len - 8) {
    if ((*(u64 *)(buffer + i + j) & *(u64 *)(mask + j)) !=
        *(u64 *)(pattern + j)) {
      break;
    }
    j += 8;
  }

  if (j < len) {
    /* len - j bytes left not grouped, before comparison we should discard the
     * top 8 - (len - j) bytes by byte shifting (multiply the shift by 8) */
    if ((*(u64 *)(buffer + i + j) & *(u64 *)(mask + j))
            << ((8 - len + j) << 3) ==
        (*(u64 *)(pattern + j)) << ((8 - len + j) << 3)) {
      j += 8;
    }
  }

  if (j >= len) {
    // we get a match
    if (flag_verbose) {
      printf("%016llX: ", vbase + i);
      for (j = 0; j < len; j++) {
        printf("%02X ", buffer[i + j]);
      }
    } else {
      printf("%016llX", vbase + i);
    }
    printf("\n");
    return 1;
  }
  return 0;
}

// Sunday algorithm, modified for masked pattern
void search(u8 *buffer, u64 vbase, i32 size, u8 *pattern, u8 *mask, i32 len) {
  if (size < len) {
    return;
  }

  i32 i, j, k, delta[256];
  for (k = 0; k <= 0xff; k++) {
    delta[k] = len + 1;
  }

  u8 M, m;
  if (flag_reverse) {
    // reversed search
    for (j = len - 1; j >= 0; j--) {

      if (mask[j] == 0xff) {
        delta[pattern[j]] = j + 1;
      } else {

        M = ~mask[j], m = 1;
        while ((m | M) != M) {
          m <<= 1;
        }

        /* k in [m, M] covers all possible wildcard bit specified by mask[j]
         * since ~mask[j] | pattern[j] is always zero, characters we should
         * update are such that c = k | pattern[j] when k | M equals to M */
        for (k = 0; k <= M; k += m) {
          if ((k | M) == M) {
            /* in reversed searching delta[c] is set to the distance to
             * position -1 */
            delta[k | pattern[j]] = j + 1;
          }
        }
      }
    }

    i = size - len;
    if (flag_quick) {

      // quick search, stop when limit is meet
      while (limit && i >= 0) {
        limit -= match(buffer, vbase, i, pattern, mask, len);
        if (i > 0) {
          i -= delta[buffer[i - 1]];
        }
      }
    } else {

      while (i >= 0) {
        match(buffer, vbase, i, pattern, mask, len);
        if (i > 0) {
          i -= delta[buffer[i - 1]];
        }
      }
    }
  } else {

    for (j = 0; j < len; j++) {

      if (mask[j] == 0xff) {
        delta[pattern[j]] = len - j;
      } else {

        M = ~mask[j], m = 1;
        while ((m | M) != M) {
          m <<= 1;
        }

        for (k = 0; k <= M; k += m) {
          if ((k | M) == M) {
            // delta[c] is set to the distance to position len
            delta[k | pattern[j]] = len - j;
          }
        }
      }
    }

    i = 0;
    if (flag_quick) {

      // quick search, stop when limit is meet
      while (limit && size - i >= len) {
        limit -= match(buffer, vbase, i, pattern, mask, len);
        if (i + len < size) {
          i += delta[buffer[i + len]];
        }
      }
    } else {

      while (size - i >= len) {
        match(buffer, vbase, i, pattern, mask, len);
        if (i + len < size) {
          i += delta[buffer[i + len]];
        }
      }
    }
  }
}

// search the target block by block
void search_object(ioobj *any, u8 *pattern, u8 *mask, i32 len) {
  u64 to_read = any->end - any->begin, already_read = 0;
  if (to_read < len) {
    return;
  }

  i32 size, ct;
  if (flag_process) {
    size = VBLOCK_SIZE;
  } else {
    size = PBLOCK_SIZE;
  }

  // buffer should be at least twice the length of pattern
  while (size < (len << 1)) {
    size <<= 1;
    if (size == 0) {
      die("error allocating search buffer");
    }
  }

  u8 *buffer = (u8 *)memset(malloc(size), 0, size);
  if (buffer == NULL) {
    die("error allocating search buffer");
  }

  if (flag_reverse) {

    seek_object(any, -size); // any->curr could be 0 if size is too large
    ct = read_object(any, buffer, size);

    /* if some bytes became invalid in (any->begin, any->end), we stop the
     * algorithm immediately */
    if (ct != to_read || ct != size) {
      die("unexpected io during searching");
    }

    search(buffer, any->curr - ct, min(to_read, size), pattern, mask, len);

    // search the buffer until already_read equals to any->end - any->begin
    if (ct == size) {

      while (limit) {
        to_read -= ct;
        already_read += ct;

        /* first len - 1 bytes from the last buffer need another check
         * any->curr could be 0 though */
        seek_object(any, -(already_read + size - (len - 1)));
        // actually we only consume at most read - (len - 1) bytes
        ct = read_object(any, buffer, size) - (len - 1);

        if (ct >= to_read) {
          search(buffer, any->curr - ct, to_read + len - 1, pattern, mask, len);
          break;
        } else if (ct == size - (len - 1)) {
          search(buffer, any->curr - ct, size, pattern, mask, len);
        } else {
          die("unexpected io during searching");
        }
      }
    }
  } else {

    seek_object(any, 0LL);
    ct = read_object(any, buffer, size);

    /* if some bytes became invalid in (any->begin, any->end), we stop the
     * algorithm immediately */
    if (ct != to_read || ct != size) {
      die("unexpected io during searching");
    }

    search(buffer, any->curr - ct, min(to_read, size), pattern, mask, len);

    // search the buffer until all bytes is consumed
    if (ct == size) {

      while (limit) {
        to_read -= ct;
        already_read += ct;

        /* there could be a match if the last len - 1 bytes and the first byte
         * of new buffer meet, so we only read size - (len - 1) bytes during
         * iteration */
        memmove(buffer, buffer + size - (len - 1), len - 1);
        ct = read_object(any, buffer + len - 1, size - (len - 1));

        // in this case all bytes are consumed, no need to step further
        if (ct >= to_read) {
          search(buffer, any->curr - ct, to_read + len - 1, pattern, mask, len);
          break;
        } else if (ct == size - (len - 1)) {
          search(buffer, any->curr - ct, size, pattern, mask, len);
        } else {
          die("unexpected io during searching");
        }
      }
    }
  }

  free(buffer);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    usage();
    return 1;
  }

  char *hex_str;
  char *object_str;
  u32 i = 0, j, hex_len = 0;
  option *opt;

  // parse options
  while (++i < argc) {
    switch (strspn(argv[i], "-")) {

    case 2: // long options
      for (opt = &opts; opt->str; opt++) {
        if (!strcmp(argv[i] + 2, opt->str)) {

          if (opt->flag != NULL) {
            // set flag for a long option
            *(opt->flag) = 1;
          }

          if (opt->param != NULL) {
            // get param for a long option
            if (i + 1 < argc) {
              *(opt->param) = argv[++i];
            } else {
              usage();
            }
          }
          break;
        }
      }

      if (!opt->str) {
        usage();
      }
      break;

    case 1: // short options
      // iterate over each character(short option)
      for (j = 1; argv[i][j]; j++) {

        for (opt = &opts; opt->str; opt++) {
          if (argv[i][j] == opt->abbr[0]) {

            if (opt->flag != NULL) {
              // set flag for a short option
              *(opt->flag) = 1;
            }

            if (opt->param != NULL) {
              if (argv[i][j + 1]) {
                // any characters after this one should be treated as param
                *(opt->param) = argv[i] + j + 1;
              } else if (i + 1 < argc) {
                *(opt->param) = argv[++i];
              } else {
                usage();
              }
              break;
            }
          }
        }

        if (!opt->str) {
          usage();
        }
      }
      break;

    case 0: // other params
      if (hex_str == NULL) {

        hex_str = argv[i];
        for (j = 0; hex_str[j]; j++) {
          if ((hex_str[j] >= '0' && hex_str[j] <= '9') ||
              (hex_str[j] >= 'a' && hex_str[j] <= 'f') ||
              (hex_str[j] >= 'A' && hex_str[j] <= 'F') || hex_str[j] == '?') {
            hex_len++;
          } else if (hex_str[j] != ' ') {
            die("invalid hex string");
          }
        }

        if (hex_len % 2 || !hex_len) {
          die("invalid/empty hex string");
        }

        // two hex character for a 8-bit
        hex_len >>= 1;
      } else if (object_str == NULL) {
        object_str = argv[i];
      } else {
        usage();
      }

    default:
      usage();
    }
  }

  if (hex_str == NULL || object_str == NULL) {
    usage();
  }

  if (flag_quick) {
    limit = atoi(limit_str);
    if (limit <= 0) {
      die("invalid value %s for search limit", limit_str);
    }
  }

  u8 *pattern = (u8 *)memset(malloc(hex_len), 0, hex_len);
  u8 *mask = (u8 *)memset(malloc(hex_len), 0, hex_len);
  if (pattern == NULL || mask == NULL) {
    die("error allocating pattern buffer");
  }

  // convert ascii string to hex pattern and mask
  u8 *h = (u8 *)hex_str, x;
  for (j = 0; j < hex_len && *h; j++) {
    if (*h == ' ') {
      h++;
      continue;
    }

    x = *h++; // the higher 4 bit
    if (x != '?') {
      x = (x & 0xf) + (((char)(x << 1) >> 7) & 0x9);
      pattern[j] |= x << 4;
      mask[j] |= 0xf0;
    }

    x = *h++; // the lower 4 bit
    if (x != '?') {
      x = (x & 0xf) + (((char)(x << 1) >> 7) & 0x9);
      pattern[j] |= x;
      mask[j] |= 0xf;
    }
  }

  ioobj *any = open_object(object_str);
  if (any == NULL) {
    die("%s is not something readable", object_str);
  } else {
    search_object(any, pattern, mask, hex_len);
  }

  close_object(any);
  free(pattern);
  free(mask);
  return 0;
}
