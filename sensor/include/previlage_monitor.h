#pragma once

#include "event_schema.h"

typedef struct
{
    int pid;
    int uid;
    int euid;
} tracked_priv_t;

typedef struct
{
    tracked_priv_t *procs;
    int count;
    int cap;
} PrivilegeMonitorState;

void privilege_monitor_init(PrivilegeMonitorState *state);
void privilege_monitor_destroy(PrivilegeMonitorState *state);

int check_privilege_changes(PrivilegeMonitorState *state, event_t **out_events, int *out_count);