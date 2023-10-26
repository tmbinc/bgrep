/* The Windows/DOS implementation of read(3) opens files in text mode by
 * default, which means that an 0x1A byte is considered the end of the file
 * unless a non-standard flag is used. Make sure it's defined even on real POSIX
 * environments
 */
#ifndef O_BINARY
#define O_BINARY 0
#endif

void print_char(unsigned char c) {
  if (32 <= c && c <= 126) {
    putchar(c);
  } else {
    printf("\\x%02x", (int)c);
  }
}

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
