#pragma once

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>

extern volatile sig_atomic_t running;

void daemonize();
void register_signal_handlers();
void cleanup_and_shutdown(int fd, char const *pidfile_path);