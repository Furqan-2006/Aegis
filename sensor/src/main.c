#include "../include/daemon.h"
#include "../include/pid_file.h"
#include "../include/process_monitor.h"
#include "../include/net_monitor.h"
#include "../include/file_integrity.h"
#include "../include/privilege_monitor.h"
#include "../include/event_emitter.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PIDFILE_PATH   "/var/run/aegisd.pid"
#define LOGFILE_PATH   "/var/log/aegis_events.log"
#define SOCKET_PATH    "/tmp/aegis.sock"
#define POLL_INTERVAL_US 200000

static const char *WATCHED_FILES[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config"
};
#define WATCHED_FILES_COUNT (sizeof(WATCHED_FILES) / sizeof(WATCHED_FILES[0]))

static void dispatch(EventEmitter *emitter, event_t *events, int count)
{
    for (int i = 0; i < count; i++)
        emit_event(emitter, &events[i]);
}

int main(void)
{
    daemonize();

    int pid_fd = pidfile_acquire(PIDFILE_PATH);
    if (pid_fd < 0)
    {
        // another instance is already running or pidfile could not be opened
        exit(1);
    }

    register_signal_handlers();

    ProcessMonitorState proc_state;
    process_monitor_init(&proc_state);

    NetMonitorState net_state;
    net_monitor_init(&net_state);

    PrivilegeMonitorState priv_state;
    privilege_monitor_init(&priv_state);

    FileIntegrityState file_state;
    file_integrity_init(&file_state, WATCHED_FILES, WATCHED_FILES_COUNT);

    EventEmitter emitter;
    if (event_emitter_init(&emitter, LOGFILE_PATH, SOCKET_PATH) < 0)
    {
        // log file failed to open 
        pidfile_release(pid_fd, PIDFILE_PATH);
        exit(1);
    }

    while (running)
    {
        event_t *events;
        int count;

        if (scan_processes(&proc_state, &events, &count) == 0)
        {
            dispatch(&emitter, events, count);
            free(events);
        }

        if (scan_connections(&net_state, &events, &count) == 0)
        {
            dispatch(&emitter, events, count);
            free(events);
        }

        if (check_privilege_changes(&priv_state, &events, &count) == 0)
        {
            dispatch(&emitter, events, count);
            free(events);
        }

        if (check_watched_files(&file_state, &events, &count) == 0)
        {
            dispatch(&emitter, events, count);
            free(events);
        }

        usleep(POLL_INTERVAL_US);
    }

    // graceful shutdown 
    event_emitter_destroy(&emitter);
    file_integrity_destroy(&file_state);
    privilege_monitor_destroy(&priv_state);
    net_monitor_destroy(&net_state);
    process_monitor_destroy(&proc_state);
    cleanup_and_shutdown(pid_fd, PIDFILE_PATH);

    return 0;
}