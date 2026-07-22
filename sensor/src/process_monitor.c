#include "../include/process_monitor.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

static int cmp(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;

    return (x > y) - (x < y);
}

static int cmp_tracked(const void *a, const void *b)
{
    const tracked_proc_t *ta = a;
    const tracked_proc_t *tb = b;
    return (ta->pid > tb->pid) - (ta->pid < tb->pid);
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

static int find_tracked(ProcessMonitorState *state, int pid)
{
    int left = 0, right = state->count - 1;

    while (left <= right)
    {
        int i = left + (right - left) / 2;

        if (state->procs[i].pid == pid)
        {
            return i;
        }
        else if (state->procs[i].pid < pid)
        {
            left = i + 1;
        }
        else
        {
            right = i - 1;
        }
    }
    return -1;
}

static int pid_in_current(int *current_pids, int current_count, int pid)
{
    int left = 0, right = current_count - 1;
    while (left <= right)
    {
        int i = left + (right - left) / 2;

        if (current_pids[i] == pid)
        {
            return 1;
        }
        else if (current_pids[i] < pid)
        {
            left = i + 1;
        }
        else
        {
            right = i - 1;
        }
    }
    return 0;
}

static void add_tracked(ProcessMonitorState *state, int pid, time_t now)
{
    if (state->count == state->cap)
    {
        state->cap *= 2;
        tracked_proc_t *temp = realloc(state->procs, state->cap * sizeof(tracked_proc_t));
        if (!temp)
            return;
        state->procs = temp;
    }
    state->procs[state->count].pid = pid;
    state->procs[state->count].spawn_time = now;
    state->count++;

    qsort(state->procs, state->count, sizeof(tracked_proc_t), cmp_tracked);
}

static void remove_tracked(ProcessMonitorState *state, int index)
{
    for (int i = index; i < state->count; i++)
    {
        state->procs[i] = state->procs[i + 1];
    }
    state->count--;
}

static void ensure_event_cap(event_t **events, int *cap, int count)
{
    if (count >= *cap)
    {
        *cap *= 2;
        event_t *temp = realloc(*events, (*cap) * sizeof(event_t));
        *events = temp;
    }
}

static void fill_common_fields(event_t *e, event_type_t type)
{
    memset(e, 0, sizeof(*e));
    e->event_type = type;
    snprintf(e->event_id, sizeof(e->event_id), "%08x-%04x-%04x-%04x-%08x%04x",
             rand(), rand() & 0xFFF, rand() & 0xFFF, rand() & 0xFFF, rand(), rand() & 0xFFF);

    time_t t = time(NULL);
    struct tm tm_utc;
    gmtime_r(&t, &tm_utc);
    strftime(e->timestamp, sizeof(e->timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

// Public Functions

void process_monitor_init(ProcessMonitorState *state)
{
    state->cap = 10;
    state->count = 0;
    state->procs = malloc(state->cap * sizeof(tracked_proc_t));
}

void process_monitor_destroy(ProcessMonitorState *state)
{
    free(state->procs);
    state->procs = NULL;
    state->count = 0;
    state->cap = 0;
}

int scan_processes(ProcessMonitorState *state, event_t **out_events, int *out_count)
{
    int *current_pids;
    int current_count;

    if (get_current_pids(&current_pids, &current_count) == -1)
    {
        return -1;
    }

    int events_cap = 10;
    int events_count = 0;
    event_t *events = malloc(events_cap * sizeof(event_t));
    time_t now = time(NULL);

    // scan spawn processes

    for (int i = 0; i < current_count; i++)
    {
        int pid = current_pids[i];

        if (find_tracked(state, pid) == -1)
        {
            ensure_event_cap(&events, &events_cap, events_count);
            event_t *e = &events[events_count++];
            fill_common_fields(e, EVENT_PROCESS_SPAWN);

            read_source_info(pid, &e->source);

            source_t parent_info;
            read_source_info(e->source.ppid, &parent_info);
            strncpy(e->detail.proc_spawn.parent_exe_path, parent_info.exe_path,
                    sizeof(e->detail.proc_spawn.parent_exe_path) - 1);
            strncpy(e->detail.proc_spawn.parent_cmdline, parent_info.cmdline,
                    sizeof(e->detail.proc_spawn.parent_cmdline) - 1);
            e->detail.proc_spawn.is_setuid = false;

            add_tracked(state, pid, now);
        }
    }

    // scan processes exits

    for (int i = state->count; i >= 0; i--)
    {
        int pid = state->procs[i].pid;
        if (!pid_in_current(current_pids, current_count, pid))
        {
            ensure_event_cap(&events, &events_cap, events_count);
            event_t *e = &events[events_count++];
            fill_common_fields(e, EVENT_PROCESS_EXIT);

            e->source.pid = pid;
            e->detail.proc_exit.exit_code = -1;
            e->detail.proc_exit.duration_alive = difftime(now, state->procs[i].spawn_time);
            e->detail.proc_exit.has_duration = true;

            remove_tracked(state, i);
        }
    }

    free(current_pids);

    *out_events = events;
    *out_count = events_count;

    return 0;
}