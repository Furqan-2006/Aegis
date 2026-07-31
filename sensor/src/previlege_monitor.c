#include "../include/privilege_monitor.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>

static int read_uid_euid(int pid, int *uid, int *euid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f))
    {
        if (strncmp(line, "Uid:", 4) == 0)
        {
            sscanf(line, "Uid: %d %d", uid, euid);
            found = 1;
            break;
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

static int is_setuid_binary(const char *exe_path)
{
    struct stat st;
    if (stat(exe_path, &st) != 0)
        return 0;
    return (st.st_mode & S_ISUID) ? 1 : 0;
}

static int find_tracked(PrivilegeMonitorState *state, int pid)
{
    for (int i = 0; i < state->count; i++)
        if (state->procs[i].pid == pid)
            return i;
    return -1;
}

static void upsert_tracked(PrivilegeMonitorState *state, int pid, int uid, int euid)
{
    int idx = find_tracked(state, pid);
    if (idx != -1)
    {
        state->procs[idx].uid = uid;
        state->procs[idx].euid = euid;
        return;
    }

    if (state->count == state->cap)
    {
        state->cap *= 2;
        tracked_priv_t *tmp = realloc(state->procs, state->cap * sizeof(tracked_priv_t));
        if (!tmp) return;
        state->procs = tmp;
    }
    state->procs[state->count].pid = pid;
    state->procs[state->count].uid = uid;
    state->procs[state->count].euid = euid;
    state->count++;
}

static void remove_tracked(PrivilegeMonitorState *state, int index)
{
    for (int i = index; i < state->count - 1; i++)
        state->procs[i] = state->procs[i + 1];
    state->count--;
}

static void ensure_event_capacity(event_t **events, int *cap, int count)
{
    if (count >= *cap)
    {
        *cap *= 2;
        event_t *tmp = realloc(*events, (*cap) * sizeof(event_t));
        *events = tmp;
    }
}

static void fill_common_fields(event_t *e, event_type_t type)
{
    memset(e, 0, sizeof(*e));
    e->event_type = type;
    snprintf(e->event_id, sizeof(e->event_id), "%08x-%04x-%04x-%04x-%08x%04x",
             rand(), rand() & 0xFFFF, rand() & 0xFFFF, rand() & 0xFFFF, rand(), rand() & 0xFFFF);

    time_t t = time(NULL);
    struct tm tm_utc;
    gmtime_r(&t, &tm_utc);
    strftime(e->timestamp, sizeof(e->timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

void privilege_monitor_init(PrivilegeMonitorState *state)
{
    state->cap = 32;
    state->count = 0;
    state->procs = malloc(state->cap * sizeof(tracked_priv_t));
}

void privilege_monitor_destroy(PrivilegeMonitorState *state)
{
    free(state->procs);
    state->procs = NULL;
    state->count = 0;
    state->cap = 0;
}

int check_privilege_changes(PrivilegeMonitorState *state, event_t **out_events, int *out_count)
{
    DIR *proc = opendir("/proc");
    if (!proc)
        return -1;

    int events_cap = 8;
    int events_count = 0;
    event_t *events = malloc(events_cap * sizeof(event_t));

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL)
    {
        if (!isdigit((unsigned char)entry->d_name[0]))
            continue;

        int is_pid = 1;
        for (int i = 0; entry->d_name[i] != '\0'; i++)
        {
            if (!isdigit((unsigned char)entry->d_name[i]))
            {
                is_pid = 0;
                break;
            }
        }
        if (!is_pid)
            continue;

        int pid = atoi(entry->d_name);
        int uid, euid;
        if (read_uid_euid(pid, &uid, &euid) != 0)
            continue; // process vanished mid-scan — skip, not fatal

        int idx = find_tracked(state, pid);
        if (idx != -1)
        {
            tracked_priv_t *prev = &state->procs[idx];
            if (prev->uid != uid || prev->euid != euid)
            {
                ensure_event_capacity(&events, &events_cap, events_count);
                event_t *e = &events[events_count++];
                fill_common_fields(e, EVENT_PRIVILEGE_CHANGE);

                e->source.pid = pid;
                e->source.uid = uid;
                e->source.euid = euid;

                char exe_path[64];
                snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
                char resolved[256] = {0};
                int len = readlink(exe_path, resolved, sizeof(resolved) - 1);
                if (len != -1)
                    resolved[len] = '\0';

                e->detail.prev_chng.old_uid = prev->uid;
                e->detail.prev_chng.old_euid = prev->euid;
                e->detail.prev_chng.new_uid = uid;
                e->detail.prev_chng.new_euid = euid;

                if (len != -1 && is_setuid_binary(resolved))
                    e->detail.prev_chng.trigger = setuid_exec;
                else if (prev->uid == uid && prev->euid != euid)
                    e->detail.prev_chng.trigger = direct_change;
                else
                    e->detail.prev_chng.trigger = unknown;
            }
        }

        upsert_tracked(state, pid, uid, euid);
    }
    closedir(proc);

    for (int i = state->count - 1; i >= 0; i--)
    {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d", state->procs[i].pid);
        struct stat st;
        if (stat(path, &st) != 0)
            remove_tracked(state, i);
    }

    *out_events = events;
    *out_count = events_count;
    return 0;
}