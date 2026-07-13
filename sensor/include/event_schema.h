#pragma once

#include <stdbool.h>

typedef enum
{
    EVENT_PROCESS_SPAWN,
    EVENT_PROCESS_EXIT,
    EVENT_NET_CONNECTION,
    EVENT_FILE_MODIFIED,
    EVENT_PRIVILEGE_CHANGE
} event_type_t;

typedef struct
{
    int pid;
    int ppid;
    int uid;
    int euid;
    char cmdline[256];
    char exe_path[256];
} source_t;

typedef enum
{
    setuid_exec,
    direct_change,
    unknown
} trigger_t;

typedef struct
{
    char local_addr[20];
    int local_port;
    char remote_addr[20];
    int remote_port;
    char state[30];
    char protocol[10];
} net_connection_detail_t;

typedef struct
{
    int exit_code;
    double duration_alive;
    bool has_duration;
} process_exit_detail_t;

typedef struct
{
    char parent_exe_path[256];
    char parent_cmdline[256];
    bool is_setuid;
} process_spawn_detail_t;

typedef struct
{
    char path[256];
    char old_hash[65];
    char new_hash[65];
    int size_before;
    bool has_size_before;
    int size_after;
    bool has_size_after;
} file_modified_detail_t;

typedef struct
{
    int old_uid;
    int old_euid;
    int new_uid;
    int new_euid;
    trigger_t trigger;
} privilege_change_detail_t;

typedef union
{
    process_spawn_detail_t proc_spawn;
    process_exit_detail_t proc_exit;
    file_modified_detail_t file_modfd;
    net_connection_detail_t net_conn;
    privilege_change_detail_t prev_chng;
} event_detail_t;

typedef struct
{
    char event_id[37];
    char timestamp[32];
    event_type_t event_type;
    source_t source;
    event_detail_t detail;
} event_t;