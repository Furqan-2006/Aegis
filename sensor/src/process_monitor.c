#include "../include/process_monitor.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

static void cmp(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;

    return (x > y) - (x < y);
}

static void read_source_info(int pid, source_t *out)
{
    char status_path[20];
    char cmdline_path[20];
    char exePath[20];

    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
    snprintf(exePath, sizeof(exePath), "/proc/%d/exe", pid);

    FILE *f1 = fopen(status_path, "r");
    if (f1 == NULL)
        return;

    char line[64];

    while (fgets(line, sizeof(line), f1))
    {
        if (strncmp(line, "PPid:", 5) == 0)
        {
            sscanf(line, "PPid: %d", &out->ppid);
        }
        else if (strncmp(line, "Uid:", 4) == 0)
        {
            sscanf(line, "Uid: %d %d", &out->uid, &out->euid);
        }
    }

    fclose(f1);

    f1 = fopen(cmdline_path, "r");
    if (f1 == NULL)
        return;

    int n = fread(out->cmdline, 1, sizeof(out->cmdline), f1);
    out->cmdline[n] = '\0';

    fclose(f1);

    int len = readlink(exePath, out->exe_path, sizeof(out->exe_path) - 1);

    if (len != -1)
    {
        out->exe_path[len] = '\0';
    }
    else
    {
        out->exe_path[0] = '\0';
    }

    out->pid = pid;
}

static int get_current_pids(int **out_pids, int *out_count)
{
    DIR *proc = opendir("/proc");
    if (proc == NULL)
        return -1;

    int cap = 64;
    int count = 0;

    int *pids = malloc(cap * sizeof(*pids));
    if (pids == NULL)
    {
        closedir(proc);
        return -1;
    }

    struct dirent *entry;

    while ((entry = readdir(proc)) != NULL)
    {
        char *name = entry->d_name;

        if (!isdigit((unsigned char)name[0]))
            continue;

        int is_pid = 1;

        for (int i = 0; name[i] != '\0'; i++)
        {
            if (!isdigit((unsigned char)name[i]))
            {
                is_pid = 0;
                break;
            }
        }

        if (!is_pid)
        {
            continue;
        }

        if (count == cap)
        {
            cap *= 2;

            int *tmp = realloc(pids, cap * sizeof(*pids));
            if (!tmp)
            {
                free(pids);
                closedir(proc);
                return -1;
            }

            pids = tmp;
        }
        pids[count++] = atoi(name);
    }

    closedir(proc);

    qsort(pids, count, sizeof(*pids), cmp);

    *out_pids = pids;
    *out_count = count;

    return 0;
}

// static