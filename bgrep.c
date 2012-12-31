// Copyright 2009 Felix Domke <tmbinc@elitedvb.net>. All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
//    1. Redistributions of source code must retain the above copyright notice, this list of
//       conditions and the following disclaimer.
// 
//    2. Redistributions in binary form must reproduce the above copyright notice, this list
//       of conditions and the following disclaimer in the documentation and/or other materials
//       provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER ``AS IS'' AND ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// The views and conclusions contained in the software and documentation are those of the
// authors and should not be interpreted as representing official policies, either expressed
// or implied, of the copyright holder.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define BGREP_VERSION "0.2"

/**
 * @brief 
 *
 * @return  void 
 * @retval   
 * @see 
 * @note 
 * @author chenyuzhen
 * @date 2012/12/15 11:23:17
 **/
void usage(){
	const char * usage_desc=
		"bgrep version: %s\n"
		"usage: bgrep <hex> [<path> [...]] [options]\n"
		"\tvalid options are\n"
		"\t\t-B NUM     -- print {NUM} bytes before matching binary \n"
		"\t\t-A NUM     -- print {NUM} bytes after matching binary \n"
		"\t\t-C NUM     -- print {NUM} bytes before and after matching binary \n";

	printf(usage_desc,BGREP_VERSION);
}

int ascii2hex(char c)
{
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

void searchfile(const char *filename, int fd, const unsigned char *value, const unsigned char *mask, int len,int before,int after)
{
	off_t offset = 0;
	unsigned char buf[1024];

	len--;

	while (1)
	{
		int r;

		memmove(buf, buf + sizeof(buf) - len, len);
		r = read(fd, buf + len, sizeof(buf) - len);

		if (r < 0)
		{
			perror("read");
			return;
		} else if (!r)
			return;

		int o, i, need;
		for (o = offset ? 0 : len; o < r; ++o)
		{
			for (i = 0; i <= len; ++i){
				if ((buf[o + i] & mask[i]) != value[i])
					break;
			}
			if (i > len)
			{
				need=before;
				printf("%s: offset:%08llX find ", filename, (unsigned long long)(offset + o - len));
				while( (o-len) < need ){
					need--;
				}
				
				for(i = need; i > 0 ; i--){
					printf("%02X",buf[o-i]);
				}
				
				for(i=0; i <= len; ++i ){
					printf("\e[1;33m%02X\e[0m",buf[o + i]);
				}
				
				need=after;
				while( o+need >=r ){
					need--;
				}
				
				for(i=1; i <= need; ++i){
					printf("%02X",buf[ o+len+i ]);
				}
			
				printf("\n");	
			}
		}

		offset += r;

	}
}

void recurse(const char *path, const unsigned char *value, const unsigned char *mask, int len,int before,int after)
{
	struct stat s;
	if (stat(path, &s))
	{
		perror("stat");
		return;
	}
	if (!S_ISDIR(s.st_mode))
	{
		int fd = open(path, O_RDONLY);
		if (fd < 0)
			perror(path);
		else
		{
			searchfile(path, fd, value, mask, len, before, after);
			close(fd);
		}
		return;
	}

	DIR *dir = opendir(path);
	if (!dir)
	{
		perror(path);
		exit(3);
	}

	struct dirent *d;
	while ((d = readdir(dir)))
	{
		if (!(strcmp(d->d_name, ".") && strcmp(d->d_name, "..")))
			continue;
		char newpath[strlen(path) + strlen(d->d_name) + 1];
		strcpy(newpath, path);
		strcat(newpath, "/");
		strcat(newpath, d->d_name);
		recurse(newpath, value, mask, len, before, after);
	}

	closedir(dir);
}

int main(int argc, char **argv)
{
	unsigned char value[0x100], mask[0x100];
	int len = 0;
	int before_count=4;
	int after_count=4;

	if (argc < 2)
	{
		usage();
		return 1;
	}

	char *h = argv[1];
	while (*h && h[1] && len < 0x100)
	{
		if (h[0] == '?' && h[1] == '?')
		{
			value[len] = mask[len] = 0;
			len++;
			h += 2;
		} else if (h[0] == ' ')
		{
			h++;
		} else
		{
			int v0 = ascii2hex(*h++);
			int v1 = ascii2hex(*h++);

			if ((v0 == -1) || (v1 == -1))
			{
				fprintf(stderr, "invalid hex string!\n");
				return 2;
			}
			value[len] = (v0 << 4) | v1; mask[len++] = 0xFF;
		}
	}

	if (!len || *h)
	{
		fprintf(stderr, "invalid/empty search string\n");
		return 2;
	}

	if (argc < 3)
		searchfile("stdin", 0, value, mask, len, before_count, after_count);
	else
	{
		int c = 2;
		int locale_argc=argc;
		while(c < argc){
			if(argv[c] && !strcmp(argv[c],"-B")){
				c++;
				if(locale_argc == argc){
					locale_argc=c;
				}
				if(c < argc && argv[c]){
					before_count=atoi(argv[c]);
				}
				c++;
			}
			else if(argv[c] && !strcmp(argv[c],"-A")){
				c++;
				if(locale_argc == argc){
					locale_argc=c;
				}
				if(c < argc && argv[c]){
					after_count=atoi(argv[c]);
				}
				c++;
			}
			else if(argv[c] && !strcmp(argv[c],"-C")){
				c++;
				if(locale_argc == argc){
					locale_argc=c;
				}
				if(c < argc && argv[c]){
					before_count=atoi(argv[c]);
					after_count=atoi(argv[c]);
				}
				c++;
			}
			else{
				c++;
			}
		}
		c=2;
		while (c < locale_argc)
			recurse(argv[c++], value, mask, len,before_count,after_count);
	}
	return 0;
}
