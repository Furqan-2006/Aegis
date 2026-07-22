#pragma once

#include "event_schema.h"
#include <time.h>

typedef struct
{
    int pid;
    time_t spawn_time;
} tracked_proc_t;

typedef struct
{
    tracked_proc_t *procs;
    int count;
    int cap;
} ProcessMonitorState;

void process_monitor_init(ProcessMonitorState *state);
void process_monitor_destroy(ProcessMonitorState *state);

int scan_processes(ProcessMonitorState *state, event_t **out_events, int *out_count);
