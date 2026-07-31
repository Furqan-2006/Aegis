#include "../include/net_monitor.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

static const char *TCP_STATES[] = {
    "UNKNOWN",
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING"};

static const char *tcp_state_name(int code)
{
    // if(code == 0x07) return "UNKNOWN";
    if (code >= 1 && code <= 0x0B)
        return TCP_STATES[code];

    return "UNKNOWN";
}

static void hex_to_ip(const char *hex, char *out, size_t out_size)
{
    unsigned int b1, b2, b3, b4;
    sscanf(hex, "%02X%02X%02X%02X", &b4, &b3, &b2, &b1);

    snprintf(out, out_size, "%u.%u.%u.%u", b1, b2, b3, b4);
}

static unsigned long find_pid_for_inode(unsigned long target_inode)
{
    DIR *proc = opendir("/proc");
    if (!proc)
        return 0;

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL)
    {
        if (!isdigit((unsigned char)entry->d_name[0]))
            continue;

        char fd_dir_path[300];
        snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%s/fd", entry->d_name);

        DIR *fd_dir = opendir(fd_dir_path);
        if (!fd_dir)
        {
            continue;
        }

        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir)) != NULL)
        {
            char link_path[600];
            char link_target[64];
            snprintf(link_path, sizeof(link_path), "%s/%s", fd_dir_path, fd_entry->d_name);

            int len = readlink(link_path, link_target, sizeof(link_target) - 1);
            if (len == -1)
            {
                continue;
            }

            link_target[len] = '\0';

            unsigned long inode;
            if (sscanf(link_target, "socket:[%lu]", &inode) == 1 && inode == target_inode)
            {
                closedir(fd_dir);
                closedir(proc);
                return atol(entry->d_name);
            }
        }
        closedir(fd_dir);
    }
    closedir(proc);
    return 0;
}

static int find_tracked_conn(NetMonitorState *state, unsigned long inode)
{
    for (int i = 0; i < state->count; i++)
    {
        if (state->conns[i].inode == inode)
        {
            return 1;
        }
    }
    return -1;
}

static void add_tracked_conn(NetMonitorState *state, unsigned long inode)
{
    if (state->count == state->cap)
    {
        state->cap *= 2;

        tracked_conn_t *tmp = realloc(state->conns, state->cap * sizeof(tracked_conn_t));
        if (!tmp)
            return;
        state->conns = tmp;
    }
    state->conns[state->count++].inode = inode;
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

void net_monitor_init(NetMonitorState *state)
{
    state->cap = 16;
    state->count = 0;
    state->conns = malloc(state->cap * sizeof(tracked_conn_t));
}

void net_monitor_destroy(NetMonitorState *state)
{
    free(state->conns);
    state->conns = NULL;
    state->count = 0;
    state->cap = 0;
}

int scan_connections(NetMonitorState *state, event_t **out_events, int *out_count)
{
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f)
        return -1;

    char line[512];
    fgets(line, sizeof(line), f); // skip header line

    int events_cap = 10;
    int events_count = 0;
    event_t *events = malloc(events_cap * sizeof(event_t));

    while (fgets(line, sizeof(line), f))
    {
        unsigned int local_addr_hex, local_port, remote_addr_hex, remote_port, state_hex;
        unsigned long inode;
        

        // Format: sl local_address rem_address st tx_rx tr:tm retrn uid timeout inode
        int matched = sscanf(line, "%*d: %8X:%X %8X:%X %X %*x:%*x %*x:%*x %*x %*d %*d %lu",
                             &local_addr_hex, &local_port,
                             &remote_addr_hex, &remote_port,
                             &state_hex, &inode);

        if (matched != 6)
            continue;

        if (find_tracked_conn(state, inode) == -1)
        {
            ensure_event_capacity(&events, &events_cap, events_count);
            event_t *e = &events[events_count++];
            fill_common_fields(e, EVENT_NET_CONNECTION);

            char local_hex_str[16], remote_hex_str[16];
            snprintf(local_hex_str, sizeof(local_hex_str), "%08X", local_addr_hex);
            snprintf(remote_hex_str, sizeof(remote_hex_str), "%08X", remote_addr_hex);
            hex_to_ip(local_hex_str, e->detail.net_conn.local_addr, sizeof(e->detail.net_conn.local_addr));
            hex_to_ip(remote_hex_str, e->detail.net_conn.remote_addr, sizeof(e->detail.net_conn.remote_addr));
            e->detail.net_conn.local_port = local_port;
            e->detail.net_conn.remote_port = remote_port;
            strncpy(e->detail.net_conn.state, tcp_state_name(state_hex), sizeof(e->detail.net_conn.state) - 1);
            strncpy(e->detail.net_conn.protocol, "tcp", sizeof(e->detail.net_conn.protocol) - 1);

            unsigned long pid = find_pid_for_inode(inode);
            e->source.pid = (int)pid;
            // pid may be 0 if not found (e.g. connection closed between read and lookup) —
            // downstream should treat pid==0 as "unknown owner"

            add_tracked_conn(state, inode);
        }
    }

    fclose(f);
    *out_events = events;
    *out_count = events_count;
    return 0;
}
