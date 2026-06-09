# bgrep

I'm terribly annoyed by the fact that grep(1) cannot look for binary
strings. I'm even more annoyed by the fact that a simple search for
"binary grep" doesn't yield a tool which could do that. So I wrote one.

Feel free to modify, branch, fork, improve.

## Building

```sh
make
```

## Installing

```sh
make install # to /user/local/bin, or
make install PREFIX=~/.local
```

Or, if you need it quickly,

```sh
curl -L 'https://github.com/tmbinc/bgrep/raw/main/bgrep.c' | gcc -O2 -x c -o $HOME/.local/bin/bgrep -
```

## Usage

```
bgrep [-r] [-B bytes] [-A bytes] [-C bytes] <hex> [<path> [...]]
bgrep [-r] -f <pattern> [-m <mask>] [<path> [...]]
```

| Option       | Description                                              |
| ------------ | -------------------------------------------------------- |
| `-B <bytes>` | print `<bytes>` of context before each match            |
| `-A <bytes>` | print `<bytes>` of context after each match             |
| `-C <bytes>` | print `<bytes>` of context before **and** after a match |
| `-r`         | recurse into directories                                |
| `-f <file>`  | read the search pattern from a file instead of `<hex>`  |
| `-m <file>`  | read a mask file (wildcard bytes for the pattern)       |

When no path is given, `bgrep` reads from standard input.

### Examples

Search a file for the byte sequence `0x42 0x42 0x42`:

```sh
bgrep 424242 firmware.bin
```

Recurse through a directory:

```sh
bgrep -r 424242 ./images
```

## License

BSD 2-Clause. See [LICENSE](LICENSE).
