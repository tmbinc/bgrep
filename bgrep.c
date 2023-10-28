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

typedef unsigned char uc;
typedef unsigned long long ull;

#ifdef _WIN32
#include <windows.h>

typedef HANDLE handle_f;

#else

#define __USE_FILE_OFFSET64 // enable lseek64
#include <unistd.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef int handle_f;

#endif

void die(const char *msg, ...) {
  va_list ap;
  va_start(ap, msg);
  vfprintf(stderr, msg, ap);
  fprintf(stderr, "\n");
  va_end(ap);
  exit(1);
}

typedef struct match {
  ull offset;
  struct match *next;
} match;

ull g_base;
match g_results = {(ull)0, (match *)NULL};
match *g_rptr = &g_results;

// Sunday algorithm, modified for masked pattern
void search(uc *buffer, int size, uc *pattern, uc *mask, int len) {
  if (size < len) {
    return;
  }

  int i, j, c, delta[256];
  uc M, m;
  for (c = 0; c <= 0xff; c++) {
    delta[c] = len + 1;
  }

  // preprocessing
  for (j = 0; j < len; j++) {
    if (mask[j] == 0xff) {
      delta[pattern[j]] = len - j;
    } else {
      M = ~mask[j], m = 1;
      while ((m | M) != M) {
        m <<= 1;
      }
      for (c = 0; c <= M; c += m) {
        if ((c | M) == M) {
          delta[c | pattern[j]] = len - j;
        }
      }
    }
  }

  // grouped by 8 bytes
  i = 0;
  while (size - i >= len) {
    j = 0;
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
      // printf("%02X\n", i);
      match *result = (match *)malloc(sizeof(match));
      if (result == NULL) {
        die("error allocating result buffer");
      }
      result->offset = g_base + i;
      result->next = (match *)NULL;
      g_rptr->next = result;
      g_rptr = result;
    }

    i += delta[buffer[i + len]];
  }
}

void usage(char **argv) {
  printf("bgrep version: %s\n", BGREP_VERSION);
  printf("usage: bgrep [options] <hex>\n");
  printf("options:\n");
  printf("  -a, --bytes-after [length]: bytes to show after the match\n");
  printf("  -b, --bytes-before [length]: bytes to show before the match\n");
  printf("  -c, --bytes-count [length]: bytes to show before and after\n");
  printf("  -p, --pid [pid]: id of process to read\n");
  printf("  -f, --file [path]: path of file to read\n");
  exit(1);
}

int g_bytes_after;
int g_bytes_before;
int g_pid;
char *g_path;
char *g_hex;

handle_f open_file(char *path) {
#ifdef _WIN32
  handle_f fileHandle =
      CreateFileA((LPCSTR)path, GENERIC_READ, FILE_SHARE_READ, NULL,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (fileHandle == INVALID_HANDLE_VALUE) {
    die("cannot open file %s", path);
  }
  DWORD fileAttributes = GetFileAttributesA((LPCSTR)path);
  if (fileAttributes == INVALID_FILE_ATTRIBUTES ||
      (fileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
    die("%s is not a regular file", path);
  }
  return fileHandle;
#else
  handle_f fd = open(path, O_RDONLY);
  struct stat fst;
  if (fstat(fd, &fst) == -1) {
    die("cannot open file %s", path);
  }
  if (!S_ISREG(fst.st_mode) || S_ISDIR(fst.st_mode)) {
    die("%s is not a regular file", path);
  }
  return fd;
#endif
}

int read_file(handle_f hf, uc *buffer, int size) {
#ifdef _WIN32
  DWORD bytesRead = -1;
  ReadFile(hf, buffer, size, &bytesRead, NULL);
  return (int)bytesRead;
#else
  return read(hf, buffer, size);
#endif
}

void close_file(handle_f hf) {
#ifdef _WIN32
  CloseHandle(hf);
#else
  close(hf);
#endif
}

void seek_file(handle_f hf, ull pos) {
#ifdef _WIN32
  if (!SetFilePointerEx(hf, (LARGE_INTEGER)pos, NULL, FILE_BEGIN)) {
    die("error setting file pointer");
  }
#else
  if (lseek(hf, pos, SEEK_SET) == -1) {
    die("error setting file pointer");
  }
#endif
}

void dump_context(handle_f hf, ull offset) {
  uc context[BUFFER_SIZE];
  ull pos = offset > g_bytes_before ? offset - g_bytes_before : 0;
  int to_read = offset - pos + g_bytes_after;
  int ct = 0, j;

  seek_file(hf, pos);
  do {
    ct = read_file(hf, context, to_read > BUFFER_SIZE ? BUFFER_SIZE : to_read);
    for (j = 0; j < ct; j++) {
      printf("%02X ", context[j]);
    }
    to_read -= ct;
  } while (ct > 0);

  printf("\n");
}

void search_file(handle_f hf, uc *pattern, uc *mask, int len) {
  int size = BUFFER_SIZE, ct;
  while (size < (len << 1)) {
    size <<= 1; // making a buffer twice the length of pattern
    if (size == 0) {
      die("error allocating search buffer");
    }
  }
  uc *buffer = (uc *)memset(malloc(size), 0, size);
  if (buffer == NULL) {
    die("error allocating search buffer");
  }

  if ((ct = read_file(hf, buffer, size)) > 0) {
    g_base = (ull)0; // set base of the results
    search(buffer, ct, pattern, mask, len);
    if (ct >= size) {
      do {
        memmove(buffer, buffer + size - (len - 1), len - 1);
        if ((ct = read_file(hf, buffer + len - 1, size - (len - 1))) > 0) {
          g_base += size - (len - 1); // set base of the results
          search(buffer, ct + len - 1, pattern, mask, len);
        }
      } while (ct >= size - (len - 1));
    }
  }

  free(buffer);
}

typedef enum parse_stat {
  PARSE_RST,
  PARSE_BAFTER,
  PARSE_BBEFORE,
  PARSE_BCOUNT,
  PARSE_PID,
  PARSE_PATH,
  PARSE_HEX
} parse_stat;

typedef struct opt_arg {
  const char *abbr;
  const char *repr;
  parse_stat opt;
} opt_arg;

opt_arg g_opts[] = {{"-p", "--pid", PARSE_PID},
                    {"-f", "--file", PARSE_PATH},
                    {"-a", "--bytes-after", PARSE_BAFTER},
                    {"-b", "--bytes-before", PARSE_BBEFORE},
                    {"-c", "--bytes-count", PARSE_BCOUNT},
                    {NULL, NULL, (parse_stat)0}};

void parse_opts(int argc, char **argv) {
  int i = 1, j, k;
  parse_stat stat = PARSE_RST;

  while (i < argc) {
    switch (stat) {
    case PARSE_RST:
      if (argv[i][0] == '-') {
        for (k = 0; k < sizeof(g_opts) / sizeof(g_opts[0]); k++) {
          if (g_opts[k].opt == 0) {
            usage(argv);
          } else if (strcmp(argv[i], g_opts[k].abbr) == 0 ||
                     strcmp(argv[i], g_opts[k].repr) == 0) {
            stat = g_opts[k].opt;
            break;
          }
        }
        i++;
      } else {
        stat = PARSE_HEX;
      }
      break;
    case PARSE_HEX:
      if (g_hex != NULL) {
        usage(argv);
      } else {
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
      }
    case PARSE_BAFTER:
      g_bytes_after = atoi(argv[i]);
      if (g_bytes_after <= 0) {
        die("invalid value %s for bytes after", argv[i]);
      }
      goto next_opt;
    case PARSE_BBEFORE:
      g_bytes_before = atoi(argv[i]);
      if (g_bytes_before <= 0) {
        die("invalid value %s for bytes after", argv[i]);
      }
      goto next_opt;
    case PARSE_BCOUNT:
      g_bytes_after = g_bytes_before = atoi(argv[i]);
      if (g_bytes_after <= 0) {
        die("invalid value %s for bytes after", argv[i]);
      } else if (g_bytes_before <= 0) {
        die("invalid value %s for bytes after", argv[i]);
      }
      goto next_opt;
    case PARSE_PID:
      if (g_path != NULL) {
        die("cannot specify both pid and path");
      } else {
        g_pid = atoi(argv[i]);
        if (g_pid <= 0) {
          die("invalid value %s for pid", argv[i]);
        }
      }
      goto next_opt;
    case PARSE_PATH:
      if (g_pid != 0) {
        die("cannot specify both pid and path");
      } else {
        g_path = argv[i];
      }
    next_opt:
      i++;
      stat = PARSE_RST;
      break;
    default:
      die("unknown error");
    }
  }
  // must specify one of pid and path
  if (g_pid == 0 && g_path == NULL) {
    die("must specify one of pid and path");
  }
  if (g_hex == NULL) {
    die("empty hex string");
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

  if (g_pid != 0) {
    // virtual bgrep
  } else {
    // physical bgrep
    handle_f hf = open_file(g_path);
    search_file(hf, pattern, mask, len);

    g_rptr = g_results.next;
    match *tptr;
    while (g_rptr != NULL) {
      tptr = g_rptr;
      g_rptr = g_rptr->next;
      printf("%016llX: ", tptr->offset);
      dump_context(hf, tptr->offset);
      free(tptr);
    }

    close_file(hf);
  }

  free(pattern);
  free(mask);
  return 0;
}
