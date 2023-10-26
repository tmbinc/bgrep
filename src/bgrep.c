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
void search(uc *bytes, int size, uc *pattern, uc *mask, int len) {
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
        if ((*(ull *)(bytes + i + j) & *(ull *)(mask + j)) << (8 - len + j) !=
            (*(ull *)(pattern + j)) << (8 - len + j)) {
          break;
        }
      } else if ((*(ull *)(bytes + i + j) & *(ull *)(mask + j)) !=
                 *(ull *)(pattern + j)) {
        break;
      }
      j += 8;
    }
    if (j >= len) {
      printf("[+] %02X\n", i);
    }
    if (i + len < size) {
      i += delta[bytes[i + len]];
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
      "usage: %s [-a bytes] [-b bytes] [-c bytes] [-p pid]|[-f file] <hex>\n",
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

uc *g_hex;
int g_pid;
char *g_path;
int g_bytes_after;
int g_bytes_before;

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
            return;
          }
          if (strcmp(argv[i], g_options[k].repr) == 0) {
            break;
          }
        }
        stat = g_options[k].opt;
        break;
      } else {
        stat = PARSE_HEX;
        break;
      }
    case PARSE_HEX:
      if (g_hex != NULL) {
        usage(argv);
        return;
      }
      g_hex = argv[i++];
      stat = PARSE_RST;
      break;
    case PARSE_BAFTER:
      g_bytes_after = atoi(argv[i++]);
      stat = PARSE_RST;
      break;
    case PARSE_BBEFORE:
      g_bytes_before = atoi(argv[i++]);
      stat = PARSE_RST;
      break;
    case PARSE_BCOUNT:
      g_bytes_after = g_bytes_before = atoi(argv[i++]);
      stat = PARSE_RST;
      break;
    case PARSE_PID:
      if (g_path != NULL) {
        usage(argv);
        return;
      }
      g_pid = atoi(argv[i++]);
      stat = PARSE_RST;
      break;
    case PARSE_PATH:
      if (g_pid != 0) {
        usage(argv);
        return;
      }
      g_path = argv[i++];
      stat = PARSE_RST;
      break;
    default:
      die("[-] unknown error");
    }
  }

  if (g_bytes_before < 0) {
    die("[-] invalid value %d for bytes before", g_bytes_before);
  } else if (g_bytes_after < 0) {
    die("[-] invalid value %d for bytes after", g_bytes_after);
  } else if (g_pid < 0) {
    die("[-] invalid value %d for pid", g_pid);
  }
}

int main(int argc, char **argv) {
  if (argc < 2) {
    usage(argv);
    return 1;
  }
  parse_opts(argc, argv);

  /* Limit the search string dynamically based on the input string.
   * The contents of value/mask may end up much shorter than argv[1],
   * but should never be longer.
   */
  const char *h = g_hex;
  size_t maxlen = strlen(g_hex);
  unsigned char *pattern = malloc(maxlen);
  unsigned char *mask = malloc(maxlen);
  int len = 0;

  if (pattern == NULL || mask == NULL) {
    die("[-] error allocating pattern buffer!");
  }

  while (*h && len < maxlen) {
    if (h[0] == '?' && h[1] == '?') {
      pattern[len] = mask[len] = 0;
      len++;
      h += 2;
    } else if (h[0] == ' ') {
      h++;
    } else {
      int v0 = ascii2hex(*h++);
      int v1 = ascii2hex(*h++);

      if ((v0 == -1) || (v1 == -1)) {
        fprintf(stderr, "[-] invalid hex string!\n");
        free(pattern);
        free(mask);
        return 2;
      }
      pattern[len] = (v0 << 4) | v1;
      mask[len++] = 0xFF;
    }
  }

  if (!len || *h) {
    fprintf(stderr, "[-] invalid/empty search string\n");
    free(pattern);
    free(mask);
    return 2;
  }

  if (g_pid != 0) {
    /* todo
     * virtual memory bgrep
     */
  } else if (g_path == NULL) {
    g_path = "stdin"; /* read from stdin */
    search_file(0, pattern, mask, len);
  } else { /* physical memory bgrep */
    int fd = open(g_path, O_RDONLY | O_BINARY);
    if (fd < 0) {
      die("[-] unable to open %s", g_path);
    } else {
      search_file(fd, pattern, mask, len);
    }
  }

  free(pattern);
  free(mask);
  return 0;
}
