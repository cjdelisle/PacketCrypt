#pragma once

#include <stdlib.h>

void FileUtil_checkDir(const char* type, const char* dir);

void FileUtil_mkNonblock(int fileno);

// This is a blast sheild for memmem because otherwise it requires
// defining _GNU_SOURCE and after doing that, who knows how many cool
// non-portable symbols will start getting used.
void* FileUtil_memmem(const void *haystack, size_t haystacklen,
                      const void *needle, size_t needlelen);
