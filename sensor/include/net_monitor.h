#pragma once

#include "event_schema.h"

typedef struct
{
    unsigned long inode;
} tracked_conn_t;

typedef struct
{
    tracked_conn_t *conns;
    int count;
    int cap;
} NetMonitorState;

void net_monitor_init(NetMonitorState *state);
void net_monitor_destroy(NetMonitorState *state);

int scan_connections(NetMonitorState *state, event_t **out_events, int *out_count);