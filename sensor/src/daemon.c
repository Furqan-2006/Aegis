#include "../include/daemon.h"
#include "../include/pid_file.h"

volatile sig_atomic_t running = 1;

static void shutdown_handler(int sig)
{
    running = 0;
}

void daemonize()
{
    pid_t pid_1 = fork();

    if (pid_1 > 0)
    {
        exit(0);
    }

    setsid();

    pid_t pid_2 = fork();

    if (pid_2 > 0)
        exit(0);

    chdir("/");
    umask(0);

    int null_fd = open("/dev/null", O_RDWR);

    dup2(null_fd, STDIN_FILENO);
    dup2(null_fd, STDOUT_FILENO);
    dup2(null_fd, STDERR_FILENO);

    close(null_fd);
}

void run_poll_loop()
{
    while (running)
    {
        // scanners/sensors will be added here when made later
        // json logger too.
        usleep(200000);
    }
}

void cleanup_and_shutdown(int fd, char const *pidfile_path)
{
    pidfile_release(fd, pidfile_path);
    exit(0);
}

void register_signal_handlers()
{
    signal(SIGTERM, shutdown_handler);
    signal(SIGINT, shutdown_handler);
}   