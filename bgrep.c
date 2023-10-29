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

#define BGREP_VER "0.3"
#define BGREP_PHY_BLK_SIZE 512
#define BGREP_VIRT_BLK_SIZE 4096

#ifdef _WIN32
#include <Windows.h>

typedef struct target {
  HANDLE id;
  u64 begin;
  u64 end;
  u64 curr;
} target;

#else

#define __USE_FILE_OFFSET64 // enable lseek64

#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

typedef struct target {
  int id;
  u64 begin;
  u64 end;
  u64 curr;
} target;

#endif

typedef struct option {
  char *str;
  char *abbr;
  u8 *flag;
  char *param;
} option;

u8 flag_process;
u8 flag_reverse;
u8 flag_verbose;
u8 flag_limit;
u32 limit;

char *limit_str;
char *target_str;
char *hex_str;

option opts[] = {{"process", "p", &flag_process, NULL},
                 {"reverse", "r", &flag_reverse, NULL},
                 {"verbose", "v", &flag_verbose, NULL},
                 {"limit", "l", &flag_limit, &limit_str},
                 {NULL, NULL, NULL, NULL}};

void usage(char **argv) {
  fprintf(stderr, "bgrep version: %s\n", BGREP_VER);
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

// abstract layer of opening
target *open_target(char *repr) {
  if (flag_process) {
    int pid = atoi(repr);
    if (pid <= 0) {
      die("cannot open process %s", repr);
    }
    target *process = (target *)malloc(sizeof(target));
#ifdef _WIN32
    process->id = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                              FALSE, (DWORD)pid);
    if (process->id == NULL) {
      die("cannot open process %s", repr);
    }

    // set the target to code section
    u64 ptr = 0, sec_size;
    while (1) {
      MEMORY_BASIC_INFORMATION mbi = {0};
      sec_size = VirtualQueryEx(process->id, ptr, &mbi,
                                sizeof(MEMORY_BASIC_INFORMATION));
      if (!sec_size) {
        die("cannot open process %s", repr);
        break;
      } else {
        // break on the code section
        if (mbi.State == MEM_COMMIT && mbi.State == MEM_IMAGE) {
          if (mbi.Protect == PAGE_EXECUTE_READ ||
              mbi.Protect == PAGE_EXECUTE_READWRITE) {
            process->begin = process->curr = ptr;
            process->end = process->begin + mbi.RegionSize;
            break;
          }
        }
      }

      ptr = mbi.BaseAddress + mbi.RegionSize;
    }
#else
    process->id = pid;

    char *buffer_file[32], buffer_line[256];
    sprintf(buffer_file, "/proc/%lld/maps", process->id);
    // set the target to code section
    int fd_maps = open(buffer_file, O_RDONLY);
    // todo: search for the code section;
    close(fd_maps);
#endif
    return process;
  } else {
    target *file = (target *)malloc(sizeof(target));
#ifdef _WIN32
    file->id = CreateFileA((LPCSTR)repr, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file->id == INVALID_HANDLE_VALUE) {
      die("cannot open file %s", repr);
    }

    // refuse to touch directories
    DWORD fileAttributes = GetFileAttributesA((LPCSTR)repr);
    if (fileAttributes == INVALID_FILE_ATTRIBUTES ||
        (fileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
      die("%s is not a regular file", repr);
    }

    // for files we set the search boundry to [0, size of file)
    file->begin = file->curr = 0LL;
    if (!GetFileSizeEx(file->id, (LARGE_INTEGER *)&file->end)) {
      die("%s is not a regular file", repr);
    }
    return file;
#else
    target *file = open(repr, O_RDONLY);
    struct stat fst;
    if (fstat(file->id, &fst) == -1) {
      die("cannot open file %s", repr);
    }

    // refuse to touch directories
    if (!S_ISREG(fst.st_mode) || S_ISDIR(fst.st_mode)) {
      die("%s is not a regular file", repr);
    }

    // for files we set the search boundry to [0, size of file)
    file->begin = file->curr = (ull)0;
    file->end = fst.st_size;
    return file;
#endif
  }
}

// abstract layer of reading
u32 read_target(target *any, u8 *buffer, u32 size) {
  if (flag_process) {
#ifdef _WIN32
    DWORD bytesRead = 0;
    if (any->curr + size > any->end) {
      ReadProcessMemory(any->id, any->curr, buffer, any->end - any->curr,
                        &bytesRead);
    } else {
      ReadProcessMemory(any->id, any->curr, buffer, size, &bytesRead);
    }
    any->curr += bytesRead;
    return bytesRead;
#else
    u32 ct;
    struct iovec local[1];
    local[0].iov_base = buffer;
    local[0].iov_len = size;
    struct iovec remote[1];
    remote[0].iov_base = any->curr;
    if (any->curr + size > any->end) {
      remote[0].iov_len = any->end - any->curr;
    } else {
      remote[0].iov_len = size;
    }
    ct = process_vm_readv(any->id, local, 1, remote, 1, 0);
    any->curr += ct;
    return ct;
#endif
  } else {
    /* we should not touch bytes outside the boundry. in order to do that, our
     * target pointer should always have the same value as file offset */
#ifdef _WIN32
    DWORD bytesRead = -1;
    if (any->curr + size > any->end) {
      ReadFile(any->id, buffer, any->end - any->curr, &bytesRead, NULL);
    } else {
      ReadFile(any->id, buffer, size, &bytesRead, NULL);
    }
    any->curr += bytesRead;
    return bytesRead;
#else
    u32 ct;
    if (any->curr + size > any->end) {
      ct = read(any->id, buffer, any->end - any->curr);
    } else {
      ct = read(any->id, buffer, size);
    }
    any->curr += ct;
    return ct;
#endif
  }
}

// abstract io layer of closing
void close_target(target *any) {
  /* for windows, any process/file is associated with a handle; for linux it's a
   * file descriptor */
#ifdef _WIN32
  CloseHandle(any->id);
#else
  close(any->id);
#endif
  free(any);
}

// abstract io layer of seeking
u64 seek_target(target *any, i64 offset) {
  i64 pos = 0;
  pos = offset >= 0 ? any->begin + offset : any->end + offset;
  /* we restrict target pointer in [any->begin, any->end), positive offsets are
   * for seeking from the beginning, negative ones for seeking from the end */
  if (pos > any->end) {
    pos = any->end;
  } else if (pos < any->begin) {
    pos = any->begin;
  }

  if (flag_process) {
    // for processes, we just set the target pointer
    any->curr = pos;
  } else {
    /* we make our target pointer track the 64-bit file offset, for windows it's
     * SetFilePointerEx, for linux it's lseek64 (define __USE_FILE_OFFSET64
     * before including unistd.h) */
#ifdef _WIN32
    LARGE_INTEGER newPos, newCurr;
    newPos.QuadPart = pos;
    SetFilePointerEx(any->id, newPos, &newCurr, FILE_BEGIN);
    any->curr = newCurr.QuadPart;
#else
    i64 curr = lseek64(any->id, pos, SEEK_SET);
    any->curr = curr;
#endif
  }

  return any->curr;
}

// 8-byte group matching
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
     * top 8 - (len - j) ones by byte shifting (multiply the shift by 8) */
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
      // preprocessing
      if (mask[j] == 0xff) {
        delta[pattern[j]] = j + 1;
      } else {
        M = ~mask[j], m = 1;
        while ((m | M) != M) {
          m <<= 1;
        }
        /* number k has M as the upper bound and m the lower bound, which should
         * cover all possible wildcard bit specified by mask[j], since ~mask[j]
         * | pattern[j] is always zero, characters we should update are such
         * that c = k | pattern[j] when k | M equals to M */
        for (k = 0; k <= M; k += m) {
          if ((k | M) == M) {
            /* in reversed searching delta[c] is set to the distance to position
             * -1 */
            delta[k | pattern[j]] = j + 1;
          }
        }
      }
    }

    i = size - len;
    if (flag_limit) {
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
    if (flag_limit) {
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
void search_target(target *any, u8 *pattern, u8 *mask, i32 len) {
  u64 to_read = any->end - any->begin, readed = 0;
  if (to_read < len) {
    return;
  }

  i32 size, ct;
  if (flag_process) {
    size = BGREP_VIRT_BLK_SIZE;
  } else {
    size = BGREP_PHY_BLK_SIZE;
  }

  // size should be at least twice the length of our pattern
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
    seek_target(any, -size);
    ct = read_target(any, buffer, size);
    if (ct < to_read && ct < size) {
      die("inconsistency during searching");
    }

    search(buffer, any->curr - ct, min(to_read, size), pattern, mask, len);

    if (size < to_read) {
      while (limit) {
        to_read -= ct;
        readed += ct;

        seek_target(any, -(readed + size - (len - 1)));
        ct = read_target(any, buffer, size);

        if (ct >= to_read) {
          search(buffer, any->curr - ct, to_read + len - 1, pattern, mask, len);
          break;
        } else if (ct == size) {
          search(buffer, any->curr - ct, size, pattern, mask, len);
        } else {
          die("inconsistency during searching");
        }
      }
    }
  } else {
    seek_target(any, 0LL);
    ct = read_target(any, buffer, size);
    if (ct < to_read && ct < size) {
      die("inconsistency during searching");
    }

    search(buffer, any->curr - ct, min(to_read, size), pattern, mask, len);

    if (size < to_read) {
      while (limit) {
        to_read -= ct;
        readed += ct;

        memmove(buffer, buffer + size - (len - 1), len - 1);
        ct = read_target(any, buffer + len - 1, size - (len - 1));

        if (ct >= to_read) {
          search(buffer, any->curr - ct, to_read + len - 1, pattern, mask, len);
          break;
        } else if (ct == size - (len - 1)) {
          search(buffer, any->curr - ct, size, pattern, mask, len);
        } else {
          die("inconsistency during searching");
        }
      }
    }
  }

  free(buffer);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    usage(argv);
    return 1;
  }

  option *k;
  u32 i, j;

  i = 0;
  while (++i < argc) {
    if (argv[i][0] == '-') {
      if (argv[i][1] == '-') {
        for (k = &opts; k->str; k++) {
          if (!strcmp(argv[i] + 2, k->str)) {
            break;
          }
        }
        if (!k->str) {
          usage(argv);
        }
        if (k->flag != NULL) {
          *(k->flag) = 1;
        }
        if (k->param != NULL) {
          *(k->param) = argv[++i];
        }
      } else {
        // short opts
        for (j = 1; argv[i][j]; j++) {
          for (k = &opts; k->str; k++) {
            if (argv[i][j] == k->abbr[0]) {
              if (k->flag != NULL) {
                *(k->flag) = 1;
              }
              if (k->param != NULL) {
                if (argv[i][j + 1]) {
                  *(k->param) = argv[i] + j + 1;
                } else if (i + 1 < argc) {
                  *(k->param) = argv[i + 1];
                } else {
                  usage(argv);
                }
              }
            }
          }
          if (!k->str) {
            usage(argv);
          }
        }
      }
    } else if (hex_str == NULL) {
      hex_str = argv[i];
      for (j = 0; hex_str[j]; j++) {
        if (hex_str[j] == '?' || hex_str[j] == ' ') {
          continue;
        } else if (hex_str[j] >= '0' && hex_str[j] <= '9') {
          continue;
        } else if (hex_str[j] >= 'a' && hex_str[j] <= 'f') {
          continue;
        } else if (hex_str[j] >= 'A' && hex_str[j] <= 'F') {
          continue;
        }
        die("invalid hex string");
      }
      if (j % 2 == 1 || j == 0) {
        die("invalid/empty hex string");
      }
    } else if (target_str == NULL) {
      target_str = argv[i];
    } else {
      usage(argv);
    }
  }

  if (hex_str == NULL || target_str == NULL) {
    usage(argv);
  }

  if (flag_limit) {
    limit = atoi(limit_str);
    if (limit <= 0) {
      die("invalid value %s for search limit", limit_str);
    }
  }

  u32 buffer_len = (strlen(hex_str) >> 1) + 1;
  u8 *pattern = (u8 *)memset(malloc(buffer_len), 0, buffer_len);
  u8 *mask = (u8 *)memset(malloc(buffer_len), 0, buffer_len);
  if (pattern == NULL || mask == NULL) {
    die("error allocating pattern buffer");
  }

  u32 len = 0;
  u8 *h = (u8 *)hex_str, x;
  while (*h && len < buffer_len) {
    if (*h == ' ') {
      h++;
      continue;
    }
    // ascii to hex
    x = *h++;
    if (x != '?') {
      x = (x & 0xf) + (((char)(x << 1) >> 7) & 0x9);
      pattern[len] |= x << 4;
      mask[len] |= 0xf0;
    }
    x = *h++;
    if (x != '?') {
      x = (x & 0xf) + (((char)(x << 1) >> 7) & 0x9);
      pattern[len] |= x;
      mask[len] |= 0xf;
    }
    len++;
  }

  target *any = open_target(target_str);
  search_target(any, pattern, mask, len);
  close_target(any);

  free(pattern);
  free(mask);
  return 0;
}
