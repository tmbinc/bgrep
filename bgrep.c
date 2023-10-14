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

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BGREP_VERSION "0.2"

// The Windows/DOS implementation of read(3) opens files in text mode by
// default, which means that an 0x1A byte is considered the end of the file
// unless a non-standard flag is used. Make sure it's defined even on real POSIX
// environments
#ifndef O_BINARY
#define O_BINARY 0
#endif

int bytes_before = 0, bytes_after = 0;

void die(const char *msg, ...) {
  va_list ap;
  va_start(ap, msg);
  vfprintf(stderr, msg, ap);
  fprintf(stderr, "\n");
  va_end(ap);
  exit(1);
}

void print_char(unsigned char c) {
  if (isprint(c))
    putchar(c);
  else
    printf("\\x%02x", (int)c);
}

int ascii2hex(char c) {
  if (c < '0')
    return -1;
  else if (c <= '9')
    return c - '0';
  else if (c < 'A')
    return -1;
  else if (c <= 'F')
    return c - 'A' + 10;
  else if (c < 'a')
    return -1;
  else if (c <= 'f')
    return c - 'a' + 10;
  else
    return -1;
}

/* TODO: this will not work with STDIN or pipes
 * 	 we have to maintain a window of the bytes before which I am too lazy to
 * do right now.
 */
void dump_context(int fd, unsigned long long pos) {
  off_t save_pos = lseek(fd, 0, SEEK_CUR);

  if (save_pos == (off_t)-1) {
    perror("lseek");
    return; /* this one is not fatal*/
  }

  char buf[1024];
  off_t start = pos - bytes_before;
  int bytes_to_read = bytes_before + bytes_after;

  if (lseek(fd, start, SEEK_SET) == (off_t)-1) {
    perror("lseek");
    return;
  }

  for (; bytes_to_read;) {
    int read_chunk = bytes_to_read > sizeof(buf) ? sizeof(buf) : bytes_to_read;
    int bytes_read = read(fd, buf, read_chunk);

    if (bytes_read < 0) {
      perror("read");
      die("Error reading context");
    }

    char *buf_end = buf + bytes_read;
    char *p = buf;

    for (; p < buf_end; p++) {
      print_char(*p);
    }

    bytes_to_read -= read_chunk;
  }

  putchar('\n');

  if (lseek(fd, save_pos, SEEK_SET) == (off_t)-1) {
    perror("lseek");
    die("Could not restore the original file offset while printing context");
  }
}

void search(const char *filename, int fd, const unsigned char *buffer, int size,
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
        printf(" [+] %s: %08llx\n", filename, i);
        if (bytes_before || bytes_after) {
          dump_context(fd, i);
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
        printf(" [+] %s: %08llx\n", filename, i - j);
        if (bytes_before || bytes_after) {
          dump_context(fd, i - j);
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

void searchfile(const char *filename, int fd, const unsigned char *value,
                const unsigned char *mask, int len) {
  int r, tail = len - 1, offset = 0;

  // use a search buffer which is at least the next power of two after len
  size_t bufsize = 1024;
  while (bufsize <= (size_t)len)
    bufsize <<= 1;
  unsigned char *buf = malloc(bufsize);

  if (!buf) {
    die("error allocating search buffer!");
  }

  while (1) {
    memmove(buf, buf + bufsize - tail, tail);
    r = read(fd, buf + tail, bufsize - tail);

    if (r < 0) {
      perror("read");
      break;
    } else if (!r)
      break;

    search(filename, fd, buf + offset, r, value, mask, len);
    offset += r;
  }

  free(buf);
}

void recurse(const char *path, const unsigned char *value,
             const unsigned char *mask, int len) {
  struct stat s;
  if (stat(path, &s)) {
    perror("stat");
    return;
  }
  if (!S_ISDIR(s.st_mode)) {
    int fd = open(path, O_RDONLY | O_BINARY);
    if (fd < 0)
      perror(path);
    else {
      searchfile(path, fd, value, mask, len);
      close(fd);
    }
    return;
  }

  DIR *dir = opendir(path);
  if (!dir) {
    perror(path);
    exit(3);
  }

  struct dirent *d;
  while ((d = readdir(dir))) {
    if (!(strcmp(d->d_name, ".") && strcmp(d->d_name, "..")))
      continue;
    char newpath[strlen(path) + strlen(d->d_name) + 1];
    strcpy(newpath, path);
    strcat(newpath, "/");
    strcat(newpath, d->d_name);
    recurse(newpath, value, mask, len);
  }

  closedir(dir);
}

void usage(char **argv) {
  fprintf(stderr, "bgrep version: %s\n", BGREP_VERSION);
  fprintf(stderr,
          "usage: %s [-B bytes] [-A bytes] [-C bytes] <hex> [<path> [...]]\n",
          *argv);
  exit(1);
}

void parse_opts(int argc, char **argv) {
  int c;

  while ((c = getopt(argc, argv, "A:B:C:")) != -1) {
    switch (c) {
    case 'A':
      bytes_after = atoi(optarg);
      break;
    case 'B':
      bytes_before = atoi(optarg);
      break;
    case 'C':
      bytes_before = bytes_after = atoi(optarg);
      break;
    default:
      usage(argv);
    }
  }

  if (bytes_before < 0)
    die("Invalid value %d for bytes before", bytes_before);
  if (bytes_after < 0)
    die("Invalid value %d for bytes after", bytes_after);
}

int main(int argc, char **argv) {
  unsigned char *value, *mask;
  int len = 0;

  if (argc < 2) {
    usage(argv);
    return 1;
  }

  parse_opts(argc, argv);
  argv += optind - 1; /* advance the pointer to the first non-opt arg */
  argc -= optind - 1;

  char *h = argv[1];
  enum { MODE_HEX, MODE_TXT, MODE_TXT_ESC } parse_mode = MODE_HEX;

  // Limit the search string dynamically based on the input string.
  // The contents of value/mask may end up much shorter than argv[1],
  // but should never be longer.
  size_t maxlen = strlen(h);
  value = malloc(maxlen);
  mask = malloc(maxlen);

  if (!value || !mask) {
    die("error allocating memory for search string!\n");
  }

  while (*h && (parse_mode != MODE_HEX || h[1]) && len < maxlen) {
    int on_quote = (h[0] == '"');
    int on_esc = (h[0] == '\\');

    switch (parse_mode) {
    case MODE_HEX:
      if (on_quote) {
        parse_mode = MODE_TXT;
        h++;
        continue; /* works under switch - will continue the loop*/
      }
      break; /* this one is for switch */
    case MODE_TXT:
      if (on_quote) {
        parse_mode = MODE_HEX;
        h++;
        continue;
      }

      if (on_esc) {
        parse_mode = MODE_TXT_ESC;
        h++;
        continue;
      }

      value[len] = h[0];
      mask[len++] = 0xff;
      h++;
      continue;

    case MODE_TXT_ESC:
      value[len] = h[0];
      mask[len++] = 0xff;
      parse_mode = MODE_TXT;
      h++;
      continue;
    }
    //
    if (h[0] == '?' && h[1] == '?') {
      value[len] = mask[len] = 0;
      len++;
      h += 2;
    } else if (h[0] == ' ') {
      h++;
    } else {
      int v0 = ascii2hex(*h++);
      int v1 = ascii2hex(*h++);

      if ((v0 == -1) || (v1 == -1)) {
        fprintf(stderr, "invalid hex string!\n");
        free(value);
        free(mask);
        return 2;
      }
      value[len] = (v0 << 4) | v1;
      mask[len++] = 0xFF;
    }
  }

  if (!len || *h) {
    fprintf(stderr, "invalid/empty search string\n");
    free(value);
    free(mask);
    return 2;
  }

  if (argc < 3)
    searchfile("stdin", 0, value, mask, len);
  else {
    int c = 2;
    while (c < argc)
      recurse(argv[c++], value, mask, len);
  }

  free(value);
  free(mask);
  return 0;
}
