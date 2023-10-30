/* bgrep - grep binary signatures
 * Forked by Yang
 *
 * THIS PROGRAM WORKS ON GNU LINUX AND WINDOWS. */

/* Copyright 2009 Felix Domke <tmbinc@elitedvb.net>. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
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

#ifdef _WIN32

#include <Windows.h>

#else

/* enable process_vm_readv */
#define _GNU_SOURCE

#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#endif

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
#define VMEM_END (1ULL << ((sizeof(u64) << 3) - 1))

#ifndef min
#define min(x, y) (x) > (y) ? (y) : (x)
#endif

#ifndef max
#define max(x, y) (x) < (y) ? (y) : (x)
#endif

#define atoh(x) (((x)&0xf) + (((i8)((x) << 1) >> 7) & 0x9))

/* universal IO object, including an id number and 3 pointers */
typedef struct data {

#ifdef _WIN32
  HANDLE id; /* universal windows handle */
#else
  u64 id; /* pid or fd */
#endif

  u64 begin;
  u64 end;
  u64 curr;
} data;

u8 flag_process;
u8 flag_verbose;
u8 flag_quick;

u32 limit; /* max number of search results */
char *limit_str;

typedef struct option {
  const char *str;  /* long option */
  const char *abbr; /* short option */
  u8 *flag;         /* flag to set if needed */
  char **param;     /* param string to set if needed */
} option;

option opts[] = {

    {"process", "p", &flag_process, NULL},
    {"verbose", "v", &flag_verbose, NULL},
    {"limit", "l", &flag_quick, &limit_str},
    {NULL, NULL, NULL, NULL}

};

void usage() {
  fprintf(stderr, "bgrep version: %s\n", BGREP_VERSION);
  fprintf(stderr, "usage: bgrep -[pv] [-l count] <hex> <target>\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -p, --process: <target> is pid instead of file path\n");
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

/* abstract IO layer of opening, returns NULL on error */
data *open_object(char *repr) {

#ifdef _WIN32

  if (flag_process) {
    data *process = (data *)malloc(sizeof(data));

    /* enable PROCESS_QUERY_INFORMATION for VirtualQueryEx */
    process->id = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                              FALSE, atoi(repr));
    if (process->id == NULL) {
      return NULL;
    }

    /* align IO object to the first code section */
    u64 pAddress = VMEM_BEGIN;
    MEMORY_BASIC_INFORMATION mbi;
    while (pAddress < VMEM_END) {

      memset(&mbi, 0, sizeof(mbi));
      if (!VirtualQueryEx(process->id, (LPCVOID)pAddress, &mbi, sizeof(mbi))) {
        break;
      }

      /* Iteration stops upon the first executable section. However sometimes it
       * may not be .text of the main program, especially for some handcrafted
       * PEs, which requires further research. */
      if (mbi.State == MEM_COMMIT && mbi.State == MEM_IMAGE &&
          (mbi.Protect == PAGE_EXECUTE_READ ||
           mbi.Protect == PAGE_EXECUTE_READWRITE)) {
        process->begin = process->curr = (u64)mbi.BaseAddress;
        process->end = process->begin + mbi.RegionSize;
        return process;
      }

      /* calculate the next possible address */
      pAddress = (u64)mbi.BaseAddress + mbi.RegionSize;
    }

    /* no .text section, refuse to open */
    return NULL;

  } else {
    data *file = (data *)malloc(sizeof(data));

    file->id = CreateFileA(repr, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file->id == INVALID_HANDLE_VALUE) {
      return NULL;
    }

    /* refuse to touch directories */
    DWORD fileAttributes = GetFileAttributesA(repr);
    if (fileAttributes == INVALID_FILE_ATTRIBUTES ||
        (fileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
      return NULL;
    }

    /* for files we set the search boundry to [0, size of file) */
    LARGE_INTEGER fileSize;
    file->begin = file->curr = 0ULL;
    if (!GetFileSizeEx(file->id, &fileSize)) {
      return NULL;
    }

    file->end = fileSize.QuadPart;
    return file;
  }

#else

  if (flag_process) {
    data *process = (data *)malloc(sizeof(data));
    char buffer_path[32], buffer_value[40];

    /* For GNU Linux processes there's no API like VirtualQuery.
     * We either use ptrace to debug it or parse /proc/<pid>/maps. */
    process->id = atoi(repr);
    sprintf(buffer_path, "/proc/%u/maps", process->id);
    FILE *fp = fopen(buffer_path, "r");
    if (fp == NULL) {
      return NULL;
    }

    char c, r, w, x;
    u64 begin, end;

    while (fgets(buffer_value, 40, fp) != NULL) {

      /* search process map and align IO object to the first code section */
      sscanf(buffer_value, "%llu-%llu %c%c%c", &begin, &end, &r, &w, &x);

      if (r == 'r' && x == 'x') {
        process->begin = process->curr = begin;
        process->end = end;
        fclose(fp);
        return process;
      }

      while ((c = getc(fp)) != EOF && c != '\n')
        ;
    }

    /* no code section, refuse to open */
    fclose(fp);
    return NULL;

  } else {
    data *file = (data *)malloc(sizeof(data));

    file->id = open(repr, O_RDONLY);
    struct stat fst;
    if (fstat(file->id, &fst) == -1) {
      return NULL;
    }

    /* refuse to touch directories */
    if (!S_ISREG(fst.st_mode) || S_ISDIR(fst.st_mode)) {
      return NULL;
    }

    /* for files we set search boundry to [0, size of file) */
    file->begin = file->curr = 0ULL;
    file->end = fst.st_size;
    return file;
  }

#endif
}

/* abstract IO layer of reading, returns -1 on error */
i32 read_object(data *any, u8 *buffer, u32 size) {

#ifdef _WIN32

  SIZE_T ct = 0; /* We should never touch bytes outside the boundry. */
  DWORD cb = any->curr + size > any->end ? any->end - any->curr : size;

  if (flag_process) {
    if (!ReadProcessMemory(any->id, (LPCVOID)any->curr, buffer, cb, &ct)) {
      return -1;
    }
  } else {
    if (!ReadFile(any->id, buffer, cb, (LPDWORD)&ct, NULL)) {
      return -1;
    }
  }

#else

  i32 ct = 0; /* We should never touch bytes outside the boundry. */
  u32 to_read = any->curr + size > any->end ? any->end - any->curr : size;

  if (flag_process) {
    struct iovec local = {.iov_base = buffer, .iov_len = size};
    struct iovec remote = {.iov_base = (void *)any->curr, .iov_len = to_read};
    ct = process_vm_readv(any->id, &local, 1, &remote, 1, 0);
  } else {
    ct = read(any->id, buffer, to_read);
  }

  if (ct == -1) {
    return -1;
  }

#endif

  /* set IO pointer to track file offset */
  any->curr += ct;
  return (u32)ct;
}

/* abstract IO layer of closing */
void close_object(data *any) {

#ifdef _WIN32
  CloseHandle(any->id);
#else
  if (!flag_process) { /* no need to close a pid */
    close(any->id);
  }
#endif

  free(any);
}

/* grouped bytes matching, if there's a match, returns $flag_quick */
u8 match(u8 *buffer, u64 vbase, u32 i, u8 *pattern, u8 *mask, i32 len) {

  u8 *start = buffer + i;

  i32 j = 0;
  while (j <= len - sizeof(u64)) {
    if ((*(u64 *)(start + j) & *(u64 *)(mask + j)) != *(u64 *)(pattern + j)) {
      break;
    }
    j += sizeof(u64);
  }

  if (j < len) {
    /* len - j bytes left not grouped
     * Before comparison we should discard the top W - (len - j) bytes. */
    u64 x = (1 << ((len - j) << 3)) - 1;
    if ((*(u64 *)(start + j) & *(u64 *)(mask + j) & x) ==
        (*(u64 *)(pattern + j) & x)) {
      j += sizeof(u64);
    }
  }

  if (j >= len) {
    /* we get a match */
    if (flag_verbose) {
      printf("%016llX: ", vbase + i);
      for (j = 0; j < len; j++) {
        printf("%02X ", start[j]);
      }
    } else {
      printf("%016llX", vbase + i);
    }
    printf("\n");
    return flag_quick;
  }

  return 0;
}

/* Sunday algorithm, modified for masked pattern */
void search(u8 *buffer, u64 vbase, i32 size, u8 *pattern, u8 *mask, i32 len) {
  if (size < len) {
    return;
  }

  i32 j, k, delta[256];
  for (k = 0; k <= 0xff; k++) {
    delta[k] = len + 1;
  }

  u8 M, m;
  for (j = 0; j < len; j++) {

    if (mask[j] == 0xff) {
      delta[pattern[j]] = len - j;
    } else {

      M = ~mask[j], m = 1;
      while ((m | M) != M) {
        m <<= 1;
      }

      /* [m, M] covers all possible wildcard bit masks specified by mask[j].
       * Since ~mask[j] | pattern[j] is always zero, characters we should
       * update are such that c = k | pattern[j] when k | M equals to M. */

      for (k = 0; k <= M; k += m) {
        if ((k | M) == M) {
          delta[k | pattern[j]] = len - j;
        }
      }
    }
  }

  i32 i = 0;
  while (limit) {
    limit -= match(buffer, vbase, i, pattern, mask, len);
    if (i + len < size) {
      i += delta[buffer[i + len]];
    } else {
      break;
    }
  }
}

/* search IO object block by block */
void search_object(data *any, u8 *pattern, u8 *mask, i32 len) {
  u64 total = any->end - any->begin;
  if (total < len) {
    return;
  }

  i32 size, ct;
  if (flag_process) {
    size = VBLOCK_SIZE;
  } else {
    size = PBLOCK_SIZE;
  }

  /* Buffer should be at least twice the length as pattern. */
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

  /* Bytes in [fwnd, rwnd) are buffered but not searched. */
  u64 fwnd = 0ULL, rwnd = 0ULL;

  while (limit && rwnd < total) {
    ct = read_object(any, buffer + (rwnd - fwnd), size - (rwnd - fwnd));
    if (ct <= 0) {
      /* If some bytes become invalid in [any->begin, any->end), we stop the
       * algorithm immediately. */
      fprintf(stderr, "unexpected IO during searching"); /* not fatal */
      break;
    }

    rwnd += ct;
    if (rwnd - fwnd >= len) {
      search(buffer, any->begin + fwnd, rwnd - fwnd, pattern, mask, len);

      /* concat the last (len - 1) bytes with the next buffer */
      memmove(buffer, buffer + ((rwnd - fwnd) - (len - 1)), len - 1);
      fwnd = rwnd - (len - 1);
    }
  }

  free(buffer);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    usage();
    return 1;
  }

  char *hex_str = NULL;
  char *object_str = NULL;
  u32 i = 0, j, hex_len = 0;
  option *opt;

  while (++i < argc) {
    switch (strspn(argv[i], "-")) {

    case 2: /* long options */
      for (opt = opts; opt->str; opt++) {
        if (!strcmp(argv[i] + 2, opt->str)) {

          if (opt->flag != NULL) {
            /* set flag for a long option */
            *(opt->flag) = 1;
          }

          if (opt->param != NULL) {
            /* get param for a long option */
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

    case 1: /* short options */
      /* iterate over each character(short option) */
      for (j = 1; argv[i][j]; j++) {

        for (opt = opts; opt->str; opt++) {
          if (argv[i][j] == opt->abbr[0]) {

            if (opt->flag != NULL) {
              /* set flag for a short option */
              *(opt->flag) = 1;
            }

            if (opt->param != NULL) {
              if (argv[i][j + 1]) {
                /* Substring after this character should be treated as param. */
                *(opt->param) = argv[i] + j + 1;
                j += strlen(argv[i] + j + 1);
              } else if (i + 1 < argc) {
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
      }
      break;

    case 0: /* other params */
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

        /* two hex character for a 8-bit */
        hex_len >>= 1;
      } else if (object_str == NULL) {
        object_str = argv[i];
      } else {
        usage();
      }
      break;

    default:
      usage();
    }
  }

  if (hex_str == NULL || object_str == NULL) {
    usage();
  }

  /* only useful in quick search mode */
  limit = flag_quick ? atoi(limit_str) : 1;
  if (limit <= 0) {
    die("invalid value %s for search limit", limit_str);
  }

  u8 *pattern = (u8 *)memset(malloc(hex_len), 0, hex_len);
  u8 *mask = (u8 *)memset(malloc(hex_len), 0, hex_len);
  if (pattern == NULL || mask == NULL) {
    die("error allocating pattern buffer");
  }

  /* convert ascii string to hex pattern and mask */
  u8 *h = (u8 *)hex_str, x;
  for (j = 0; j < hex_len && *h; j++) {
    x = *h++;
    if (x == ' ') {
      continue;
    }

    if (x != '?') {
      x = atoh(x); /* the higher 4 bit */
      pattern[j] |= x << 4;
      mask[j] |= 0xf0;
    }

    x = *h++;
    if (x != '?') {
      x = atoh(x); /* the lower 4 bit */
      pattern[j] |= x;
      mask[j] |= 0xf;
    }
  }

  data *any = open_object(object_str);
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
