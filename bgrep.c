/* a fork of bgrep
 * m0zikit0 <three1518@163.com>
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

#include <fcntl.h>
#include <unistd.h>

#define BGREP_VERSION "0.2"

void die(const char *msg, ...) {
  va_list ap;
  va_start(ap, msg);
  vfprintf(stderr, msg, ap);
  fprintf(stderr, "\n");
  va_end(ap);
  exit(1);
}

void print_char(unsigned char c) {
  if (32 <= c && c <= 126) {
    putchar(c);
  } else {
    printf("\\x%02x", (int)c);
  }
}

int ascii2hex(unsigned char c) {
  if (c >= 0x30 && c <= 0x39) {
    return c - 0x30;
  } else if (c >= 0x41 && c <= 0x46) {
    return c - 0x41 + 10;
  } else if (c >= 0x61 && c <= 0x66) {
    return c - 0x61 + 10;
  } else {
    return -1;
  }
}

int g_bytes_before;
int g_bytes_after;
const unsigned char *g_hex;
const char *g_path;
int g_pid;

/* TODO: this will not work with STDIN or pipes
 * We have to maintain a window of the bytes before
 * which I am too lazy to do right now.
 */
void dump_content(int fd, unsigned long long pos) {
  int save_pos = lseek(fd, 0, SEEK_CUR);

  if (save_pos == -1) {
    perror("[-] lseek");
    return; /* this one is not fatal*/
  }

  char buf[1024];
  int start = pos - g_bytes_before;
  int bytes_to_read = g_bytes_before + g_bytes_after;

  if (lseek(fd, start, SEEK_SET) == -1) {
    perror("[-] lseek");
    return;
  }

  while (bytes_to_read > 0) {
    int read_chunk = bytes_to_read > sizeof(buf) ? sizeof(buf) : bytes_to_read;
    int bytes_read = read(fd, buf, read_chunk);

    if (bytes_read < 0) {
      die("[-] error reading context");
    }

    char *buf_end = buf + bytes_read;
    char *p = buf;

    for (; p < buf_end; p++) {
      print_char(*p);
    }

    bytes_to_read -= read_chunk;
  }

  putchar('\n');

  if (lseek(fd, save_pos, SEEK_SET) == (int)-1) {
    die("[-] could not restore the original file offset while printing "
        "context");
  }
}

void search(int fd, const unsigned char *buffer, int size,
            const unsigned char *pattern, const unsigned char *mask, int len) {
  int i, j, any_wildcard;
  for (j = 0, any_wildcard = 0; j < len; j++) {
    if (mask[j] != 0xFF) {
      any_wildcard = 1;
      break;
    }
  }

  if (any_wildcard) {
    printf("[+] searching through brute force\n");
    i = j = 0;
    while (size - i >= len) {
      for (j = 0; j < len; j++) {
        if ((buffer[i + j] & mask[j]) != pattern[j]) {
          break;
        }
      }
      if (j == len) {
        printf(" [+] %s: %08llx\n", g_path, i);
        if (g_bytes_before || g_bytes_after) {
          dump_content(fd, i);
        }
      }
      i++;
    }
  } else {
    int k = 0;
    int *lps = (int *)malloc(sizeof(int) * len);
    if (lps == NULL)
      perror("[-] malloc");

    printf("[+] searching through KMP\n");
    /* pre-process lps array */
    lps[0] = 0, j = 1;
    while (j < len) {
      if (pattern[j] == pattern[k]) {
        lps[j++] = ++k; /* k pins the longest prefix */
      } else if (k != 0) {
        k = lps[k - 1]; /* shorter prefix possible... */
      } else {
        lps[j++] = 0; /* no prefix suffix here */
      }
    }

    /*
     * implementation of the KMP algorithm
     * pre-process the longest prefix suffix value
     * **produces wrong answers when there's a wild card**
     */
    i = j = 0;
    while (size - i >= len - j) {
      if (j == len) {
        /* found a match, continue at the longest prefix suffix */
        printf(" [+] %s: %08llx\n", g_path, i - j);
        if (g_bytes_before || g_bytes_after) {
          dump_content(fd, i - j);
        }
        j = lps[j - 1];
        continue;
      }
      if (pattern[j] == buffer[i]) {
        i++, j++;
      } else if (j != 0) {
        j = lps[j - 1]; /* shorter prefix possible */
      } else {
        i++; /* give up because no prefix suffix available */
      }
    }
  }
}

void search_file(int fd, const unsigned char *value, const unsigned char *mask,
                 int len) {
  int r, tail = len - 1, offset = 0;
  size_t bufsize = 1024;
  /* use a search buffer which is at least the next power of two after len */
  while (bufsize <= (size_t)len)
    bufsize <<= 1;

  unsigned char *buf = malloc(bufsize);
  if (!buf) {
    die("[-] error allocating search buffer!");
  }

  while (1) {
    memmove(buf, buf + bufsize - tail, tail);
    r = read(fd, buf + tail, bufsize - tail);

    if (r < 0) {
      perror("read");
      break;
    } else if (!r)
      break;

    search(fd, buf + offset, r, value, mask, len);
    offset += r;
  }

  free(buf);
}

void usage(char **argv) {
  fprintf(stderr, "bgrep version: %s\n", BGREP_VERSION);
  fprintf(stderr,
          "usage: %s [-a bytes] [-b bytes] [-c bytes] [-p pid] <hex> <path>\n",
          *argv);
  fprintf(stderr, " -a bytes to show after the match\n"
                  " -b bytes to show before the match\n"
                  " -c bytes count, both before and after\n"
                  " -p process id/-f file path\n");
  exit(1);
}

typedef enum {
  PARSE_RST,
  PARSE_HEX,
  PARSE_BAFTER,
  PARSE_BBEFORE,
  PARSE_BCOUNT,
  PARSE_PID,
  PARSE_PATH
} parse_stat;

struct {
  const char *repr;
  parse_stat opt;
} g_options[] = {{"-a", PARSE_BAFTER},  {"--bytes-after", PARSE_BAFTER},
                 {"-b", PARSE_BBEFORE}, {"--bytes-before", PARSE_BBEFORE},
                 {"-c", PARSE_BCOUNT},  {"--bytes-count", PARSE_BCOUNT},
                 {"-p", PARSE_PID},     {"--pid", PARSE_PID},
                 {"-f", PARSE_PATH},    {"--file", PARSE_PATH},
                 {NULL, (parse_stat)0}};

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

/* The Windows/DOS implementation of read(3) opens files in text mode by
 * default, which means that an 0x1A byte is considered the end of the file
 * unless a non-standard flag is used. Make sure it's defined even on real POSIX
 * environments
 */
#ifndef O_BINARY
#define O_BINARY 0
#endif

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
