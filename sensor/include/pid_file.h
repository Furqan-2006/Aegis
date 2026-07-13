#pragma once

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <unistd.h>
#include <string.h>

int pidfile_acquire(const char *pidfile_path);
void pidfile_release(int fd, const char *pidfile_path);
