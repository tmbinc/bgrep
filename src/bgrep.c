/* a fork of bgrep
 * mozkito <three1518@163.com>
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
 * policies, either expressed or implied, of the copyright holder.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BGREP_VERSION "0.3"

typedef unsigned char uc;
typedef unsigned long long ull;

/* Sunday algorithm
 * modified for masked pattern
 */
void search(uc *buffer, int size, uc *pattern, uc *mask, int len) {
  if (size < len) {
    return;
  }

  int i, j, delta[256];
  uc c, M, m;
  for (c = 0; c < 256; c++) {
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
    while (j < len) {
      if (j + 8 > len) {
        if ((*(ull *)(buffer + i + j) & *(ull *)(mask + j)) << (8 - len + j) !=
            (*(ull *)(pattern + j)) << (8 - len + j)) {
          break;
        }
      } else if ((*(ull *)(buffer + i + j) & *(ull *)(mask + j)) !=
                 *(ull *)(pattern + j)) {
        break;
      }
      j += 8;
    }
    if (j >= len) {
      // we get a match
      printf("%02X\n", i);
    }
    if (i + len < size) {
      i += delta[buffer[i + len]];
    }
  }
}

void die(const char *msg, ...) {
  va_list ap;
  va_start(ap, msg);
  vfprintf(stderr, msg, ap);
  fprintf(stderr, "\n");
  va_end(ap);
  exit(1);
}

void usage(char **argv) {
  fprintf(stderr, "bgrep version: %s\n", BGREP_VERSION);
  fprintf(
      stderr,
      "usage: %s [-a bytes] [-b bytes] [-c bytes] [-p pid]|[-f path] <hex>\n",
      *argv);
  fprintf(stderr, " -a --bytes-after  bytes to show after the match\n"
                  " -b --bytes-before bytes to show before the match\n"
                  " -c --bytes-count  bytes to show before and after\n"
                  " -p --pid          process id\n"
                  " -f --file         path of file to read\n");
  exit(1);
}

typedef enum {
  PARSE_RST,
  PARSE_BAFTER,
  PARSE_BBEFORE,
  PARSE_BCOUNT,
  PARSE_PID,
  PARSE_PATH,
  PARSE_HEX
} parse_stat;

struct {
  const char *repr;
  parse_stat opt;
} g_options[] = {{"-p", PARSE_PID},     {"--pid", PARSE_PID},
                 {"-f", PARSE_PATH},    {"--file", PARSE_PATH},
                 {"-a", PARSE_BAFTER},  {"--bytes-after", PARSE_BAFTER},
                 {"-b", PARSE_BBEFORE}, {"--bytes-before", PARSE_BBEFORE},
                 {"-c", PARSE_BCOUNT},  {"--bytes-count", PARSE_BCOUNT},
                 {NULL, (parse_stat)0}};

int g_bytes_after;
int g_bytes_before;
int g_pid;
char *g_path;
char *g_hex;

void parse_opts(int argc, char **argv) {
  int i = 1, j, k;
  parse_stat stat = PARSE_RST;

  while (i < argc) {
    switch (stat) {
    case PARSE_RST:
      if (argv[i][0] == '-') {
        for (k = 0; k < sizeof(g_options) / sizeof(g_options[0]); k++) {
          if (g_options[k].repr == NULL) {
            usage(argv);
          } else if (strcmp(argv[i], g_options[k].repr) == 0) {
            stat = g_options[k].opt;
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
  uc *j = (uc *)g_hex, j0, j1;
  while (*j && len < plen) {
    if (*j == ' ') {
      j++;
      continue;
    }
    // ascii to hex
    if (*j != '?') {
      j1 = (*j & 0xf) + ((*j >> 6) & 0xa);
      pattern[len] |= j1 << 4;
      mask[len] |= 0xf0;
    }
    if (*(j + 1) != '?') {
      j0 = (*(j + 1) & 0xf) + ((*(j + 1) >> 6) & 0xa);
      pattern[len] |= j0;
      mask[len++] |= 0xf;
    }
    j += 2;
  }

  if (g_pid != 0) {
    // virtual bgrep
  } else if (g_path == NULL) {
    // stdin bgrep
  } else {
    // physical bgrep
  }

  // printf("bytes_after: %d\nbytes_before: %d\npid: %d\npath: %s\nhex: %s\n",
  //        g_bytes_after, g_bytes_before, g_pid, g_path, g_hex);

  free(pattern);
  free(mask);
  return 0;
}
