#include "../include/pid_file.h"

int pidfile_acquire(const char *pidfile_path)
{
    int fd = open(pidfile_path, O_CREAT | O_RDWR, 0644);
    if (fd < 0)
    {
        perror("Could not open pidfile!!\n");
        return -1;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) == -1)
    {
        if (errno == EWOULDBLOCK)
        {
            perror("Another instance has already accquired it!");
        }
        close(fd);
        return -1;
    }

    ftruncate(fd, 0);

    char buffer[12];
    int len = snprintf(buffer, sizeof(buffer), "%d", getpid());
    buffer[len] = '\n';

    write(fd, buffer, len + 1);

    return fd;
}

void pidfile_release(int fd, const char *pidfile_path)
{
    close(fd);
    unlink(pidfile_path);
}