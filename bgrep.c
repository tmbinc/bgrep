/* Grep binary signatures
   Forked by mozkito <three1518@163.com>

   Copyright 2009 Felix Domke <tmbinc@elitedvb.net>. All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

      1. Redistributions of source code must retain the above copyright notice,
      this list of
         conditions and the following disclaimer.

      2. Redistributions in binary form must reproduce the above copyright
      notice, this list
         of conditions and the following disclaimer in the documentation and/or
         other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER ``AS IS'' AND ANY EXPRESS
   OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
   EVENT SHALL <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   The views and conclusions contained in the software and documentation are
   those of the authors and should not be interpreted as representing official
   policies, either expressed or implied, of the copyright holder.  */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BGREP_VERSION "0.3"
#define BUFFER_SIZE 1024

#define MODE_PROCESS 0x01
#define MODE_VERBOSE 0x10
#define MODE_REVERSE 0x20
#define MODE_QUICK 0x40

typedef unsigned char uc;
typedef unsigned long long ull;
typedef long long ll;

#ifdef _WIN32
#include <windows.h>

typedef struct target {
  HANDLE id;
  QWORD begin;
  QWORD end;
  QWORD curr;
}

#else

#define __USE_FILE_OFFSET64 // enable lseek64
#include <unistd.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef struct target {
  int id;
  ull begin;
  ull end;
  ull curr;
} target;

#endif

typedef enum parse_stat {
  PARSE_OPT,
  PARSE_PROC,
  PARSE_FILE,
  PARSE_REV,
  PARSE_VERBO,
  PARSE_LIM,
  PARSE_HEX,
  PARSE_TARGET
} parse_stat;

typedef struct opt {
  const char *abbr;
  const char *repr;
  parse_stat opt;
} opt;

opt g_opts[] = {
    {"-p", "--process", PARSE_PROC}, {"-f", "--file", PARSE_FILE},
    {"-r", "--reverse", PARSE_REV},  {"-v", "--verbose", PARSE_VERBO},
    {"-l", "--limit", PARSE_LIM},    {NULL, NULL, (parse_stat)0}};

char *g_hex;
char *g_target;
int g_mode;
int g_limit;

void usage(char **argv) {
  printf("bgrep version: %s\n", BGREP_VERSION);
  printf("usage: bgrep -[pfrv] [-l limit] <hex> <target>\n");
  printf("options:\n");
  printf("  -p, --process: virtual mode, <target> is pid\n");
  printf("  -f, --file: physical mode (default), <target> is path of file\n");
  printf("  -r, --reverse: reversed search\n");
  printf("  -v, --verbose: show both address and binary\n");
  printf("  -l, --limit [count]: max number of results to show\n");
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

target *open_target(char *repr) {
  if (g_mode & MODE_PROCESS) {
    target *process = (target *)malloc(sizeof(target));
#ifdef _WIN32
    // todo: win proc
#else
    // todo: linux proc
#endif
    return process;
  } else {
    target *file = (target *)malloc(sizeof(target));
#ifdef _WIN32
    file->id = CreateFileA((LPCSTR)path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file->id == INVALID_HANDLE_VALUE) {
      die("cannot open file %s", repr);
    }

    DWORD fileAttributes = GetFileAttributesA((LPCSTR)path);
    if (fileAttributes == INVALID_FILE_ATTRIBUTES ||
        (fileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
      die("%s is not a regular file", repr);
    }

    file->begin = file->curr = (QWORD)0;
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

    if (!S_ISREG(fst.st_mode) || S_ISDIR(fst.st_mode)) {
      die("%s is not a regular file", repr);
    }

    file->begin = file->curr = (ull)0;
    file->end = fst.st_size;
    return file;
#endif
  }
}

int read_target(target *any, uc *buffer, int size) {
  if (g_mode & MODE_PROCESS) {
#ifdef _WIN32
    // todo: win proc
#else
    // todo: linux proc
#endif
    return 0;
  } else {
#ifdef _WIN32
    DWORD bytesRead = -1;
    if (any->curr + size > any->end) {
      ReadFile(any->id, buffer, any->end - any->curr, &bytesRead, NULL);
    } else {
      ReadFile(any->id, buffer, size, &bytesRead, NULL);
    }
    any->curr += ct;
    return (int)bytesRead;
#else
    int ct;
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

void close_target(target *any) {
  if (g_mode & MODE_PROCESS) {
#ifdef _WIN32
    // todo: win proc
#else
    // todo: linux proc
#endif
  } else {
#ifdef _WIN32
    CloseHandle(any->id);
#else
    close(any->id);
#endif
  }
  free(any);
}

ull seek_target(target *any, ll offset) {
  ull pos = 0;
  if (offset >= 0) {
    pos = any->begin + offset;
    if (pos > any->end) {
      pos = any->end;
    }
  } else {
    pos = any->end + offset;
    if (pos < any->begin) {
      pos = any->begin;
    }
  }

  if (g_mode & MODE_PROCESS) {
#ifdef _WIN32
    // todo: win proc
#else
    // todo: linux proc
#endif
    return any->begin;
  }
#ifdef _WIN32
  LARGE_INTEGER newPos, newCurr;
  newPos.QuadPart = pos;
  if (!SetFilePointerEx(file->id, newPos, &newCurr, FILE_BEGIN)) {
    die("error setting read pointer");
  } else {
    any->curr = (ull)newCurr.QuadPart;
  }
#else
  ll curr = lseek(any->id, pos, SEEK_SET);
  if (curr == -1) {
    die("error setting read pointer");
  } else {
    any->curr = curr;
  }
#endif
}

// 8-byte group matching
int match(uc *buffer, ull vbase, int i, uc *pattern, uc *mask, int len) {
  int j = 0;
  while (j <= len - 8) {
    if ((*(ull *)(buffer + i + j) & *(ull *)(mask + j)) !=
        *(ull *)(pattern + j)) {
      break;
    }
    j += 8;
  }
  if (j < len) {
    if ((*(ull *)(buffer + i + j) & *(ull *)(mask + j)) << (8 - len + j) ==
        (*(ull *)(pattern + j)) << (8 - len + j)) {
      j += 8;
    }
  }

  if (j >= len) {
    // we get a match
    printf("%016llX: ", vbase + i);
    for (j = 0; j < len; j++) {
      printf("%02X ", buffer[i + j]);
    }
    printf("\n");
    return 1;
  } else {
    return 0;
  }
}

// Sunday algorithm, modified for masked pattern
void search(uc *buffer, ull vbase, int size, uc *pattern, uc *mask, int len) {
  if (size < len) {
    return;
  }

  int i, j, k, delta[256];
  for (k = 0; k <= 0xff; k++) {
    delta[k] = len + 1;
  }

  // preprocessing
  uc M, m;
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
          delta[k | pattern[j]] = len - j;
        }
      }
    }
  }

  i = 0;
  if (g_mode & MODE_QUICK) {
    while (g_limit && size - i >= len) {
      g_limit -= match(buffer, vbase, i, pattern, mask, len);
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

// reversed Sunday
void rsearch(uc *buffer, ull vbase, int size, uc *pattern, uc *mask, int len) {
  if (size < len) {
    return;
  }

  int i, j, k, delta[256];
  for (k = 0; k <= 0xff; k++) {
    delta[k] = len + 1;
  }

  // preprocessing
  uc M, m;
  for (j = len - 1; j >= 0; j--) {
    if (mask[j] == 0xff) {
      delta[pattern[j]] = j + 1;
    } else {
      M = ~mask[j], m = 1;
      while ((m | M) != M) {
        m <<= 1;
      }
      for (k = 0; k <= M; k += m) {
        if ((k | M) == M) {
          delta[k | pattern[j]] = j + 1;
        }
      }
    }
  }

  i = size - len;
  if (g_mode & MODE_QUICK) {
    while (g_limit && i >= 0) {
      g_limit -= match(buffer, vbase, i, pattern, mask, len);
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
}

// search the target block by block
void search_target(target *any, uc *pattern, uc *mask, int len) {
  ull to_read = any->end - any->begin, readed = 0;
  ull prev;
  if (to_read < len) {
    return;
  }

  int size = BUFFER_SIZE, ct;
  while (size < (len << 2)) {
    size <<= 1; // making a buffer 4 times the length of pattern
    if (size == 0) {
      die("error allocating search buffer");
    }
  }

  uc *buffer = (uc *)memset(malloc(size), 0, size);
  if (buffer == NULL) {
    die("error allocating search buffer");
  }

  if (g_mode & MODE_REVERSE) {
    seek_target(any, -size);
    prev = any->curr;
    ct = read_target(any, buffer, size);

    if (ct >= to_read) {
      rsearch(buffer, prev, to_read, pattern, mask, len);
    } else if (ct == size) {

      while (g_limit) {
        to_read -= ct;
        readed += ct;

        seek_target(any, -(readed + size - (len - 1)));
        prev = any->curr;
        ct = read_target(any, buffer, size);

        if (ct >= to_read) {
          rsearch(buffer, prev, to_read + len - 1, pattern, mask, len);
          break;
        } else if (ct == size) {
          rsearch(buffer, prev, size, pattern, mask, len);
        } else {
          die("inconsistency during searching");
        }
      }
    } else {
      die("inconsistency during searching");
    }

  } else {
    seek_target(any, (ll)0);
    prev = any->curr;
    ct = read_target(any, buffer, size);

    if (ct >= to_read) {
      search(buffer, prev, to_read, pattern, mask, len);
    } else if (ct == size) {

      while (g_limit) {
        to_read -= ct;
        readed += ct;

        memmove(buffer, buffer + size - (len - 1), len - 1);
        prev = any->curr;
        ct = read_target(any, buffer + len - 1, size - (len - 1));

        if (ct >= to_read) {
          search(buffer, prev, to_read + len - 1, pattern, mask, len);
          break;
        } else if (ct == size - (len - 1)) {
          search(buffer, prev, size, pattern, mask, len);
        } else {
          die("inconsistency during searching");
        }
      }
    } else {
      die("inconsistency during searching");
    }
  }

  free(buffer);
}

void parse_opts(int argc, char **argv) {
  int i = 1, j, k;
  parse_stat stat = PARSE_OPT;

  while (i < argc) {
    switch (stat) {
    case PARSE_OPT:
      if (argv[i][0] == '-') {
        for (k = 0; k < sizeof(g_opts) / sizeof(g_opts[0]); k++) {
          if (g_opts[k].opt == (parse_stat)0) {
            usage(argv);
          } else if (!strcmp(argv[i], g_opts[k].abbr) ||
                     !strcmp(argv[i], g_opts[k].repr)) {
            stat = g_opts[k].opt;
            break;
          }
        }
        i++;
      } else if (g_hex == NULL) {
        stat = PARSE_HEX;
      } else if (g_target == NULL) {
        stat = PARSE_TARGET;
      } else {
        usage(argv);
      }
      break;
    case PARSE_HEX:
      g_hex = argv[i];
      for (j = 0; g_hex[j]; j++) {
        if (g_hex[j] == '?' || g_hex[j] == ' ') {
          continue;
        } else if (g_hex[j] >= '0' && g_hex[j] <= '9') {
          continue;
        } else if (g_hex[j] >= 'a' && g_hex[j] <= 'f') {
          continue;
        } else if (g_hex[j] >= 'A' && g_hex[j] <= 'F') {
          continue;
        }
        die("invalid hex string");
      }
      if (j % 2 == 1 || j == 0) {
        die("invalid/empty hex string");
      }
      goto next_opt;
    case PARSE_TARGET:
      g_target = argv[i];
      goto next_opt;
    case PARSE_PROC:
      g_mode |= MODE_PROCESS;
      goto next_opt;
    case PARSE_FILE:
      if (g_mode & MODE_PROCESS) {
        usage(argv);
      }
      goto next_opt;
    case PARSE_REV:
      g_mode |= MODE_REVERSE;
      goto next_opt;
    case PARSE_VERBO:
      g_mode |= MODE_VERBOSE;
      goto next_opt;
    case PARSE_LIM:
      g_mode |= MODE_QUICK;
      g_limit = atoi(argv[i]);
      if (g_limit <= 0) {
        die("invalid value %s for search limit", argv[i]);
      }
    next_opt:
      i++;
      stat = PARSE_OPT;
      break;
    default:
      die("unknown error");
    }
  }
  if (g_hex == NULL || g_target == NULL) {
    usage(argv);
  }
}

int main(int argc, char **argv) {
  if (argc < 2) {
    usage(argv);
    return 1;
  }
  parse_opts(argc, argv);

  int plen = (strlen(g_hex) >> 1) + 1;
  uc *pattern = (uc *)memset(malloc(plen), 0, plen);
  uc *mask = (uc *)memset(malloc(plen), 0, plen);
  if (pattern == NULL || mask == NULL) {
    die("error allocating pattern buffer");
  }

  int len = 0;
  uc *j = (uc *)g_hex, x;
  while (*j && len < plen) {
    if (*j == ' ') {
      j++;
      continue;
    }
    // ascii to hex
    x = *j++;
    if (x != '?') {
      x = (x & 0xf) + (((char)(x << 1) >> 7) & 0x9);
      pattern[len] |= x << 4;
      mask[len] |= 0xf0;
    }
    x = *j++;
    if (x != '?') {
      x = (x & 0xf) + (((char)(x << 1) >> 7) & 0x9);
      pattern[len] |= x;
      mask[len] |= 0xf;
    }
    len++;
  }

  target *any = open_target(g_target);
  search_target(any, pattern, mask, len);
  close_target(any);

  free(pattern);
  free(mask);
  return 0;
}
