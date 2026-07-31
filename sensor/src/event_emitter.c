#include "../include/event_emitter.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

static const char *EVENT_TYPE_NAMES[] = {
    "process_spawn",
    "process_exit",
    "net_connection",
    "file_modified",
    "privilege_change"
};

static const char *TRIGGER_NAMES[] = {
    "setuid_exec",
    "direct_change",
    "unknown"
};

static void json_escape(const char *in, char *out, size_t out_size)
{
    size_t j = 0;
    for(size_t i = 0; in[i] != '\0' && j + 2 < out_size; i++)
    {
        if (in[i] == '"' || in[i] == '\\')
        {
            out[j++] = '\\';
        }
        out[j++] = in[i];
    }
    out[j] = '\0';
}

static int try_connect_socket(const char *sock_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) -1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

int event_emitter_init(EventEmitter *emitter, const char *log_path, const char *sock_path)
{
    emitter->log_file = fopen(log_path, "a");
    if (!emitter->log_file)
        return -1; 

    strncpy(emitter->sock_path, sock_path, sizeof(emitter->sock_path) - 1);
    emitter->sock_path[sizeof(emitter->sock_path) - 1] = '\0';

    emitter->sock_fd = try_connect_socket(sock_path);

    return 0;
}

static int build_json(const event_t *e, char *buf, size_t buf_size)
{
    char cmdline_esc[512], exe_esc[512], detail_buf[2048];
    json_escape(e->source.cmdline, cmdline_esc, sizeof(cmdline_esc));
    json_escape(e->source.exe_path, exe_esc, sizeof(exe_esc));

    switch (e->event_type)
    {
        case EVENT_PROCESS_SPAWN:
        {
            char parent_exe_esc[512], parent_cmd_esc[512];
            json_escape(e->detail.proc_spawn.parent_exe_path, parent_exe_esc, sizeof(parent_exe_esc));
            json_escape(e->detail.proc_spawn.parent_cmdline, parent_cmd_esc, sizeof(parent_cmd_esc));
            snprintf(detail_buf, sizeof(detail_buf),
                "{\"parent_exe_path\":\"%s\",\"parent_cmdline\":\"%s\",\"is_setuid\":%s}",
                parent_exe_esc, parent_cmd_esc,
                e->detail.proc_spawn.is_setuid ? "true" : "false");
            break;
        }
        case EVENT_PROCESS_EXIT:
        {
            if (e->detail.proc_exit.has_duration)
                snprintf(detail_buf, sizeof(detail_buf),
                    "{\"exit_code\":%d,\"duration_seconds\":%.3f}",
                    e->detail.proc_exit.exit_code, e->detail.proc_exit.duration_alive);
            else
                snprintf(detail_buf, sizeof(detail_buf),
                    "{\"exit_code\":%d}", e->detail.proc_exit.exit_code);
            break;
        }
        case EVENT_NET_CONNECTION:
        {
            snprintf(detail_buf, sizeof(detail_buf),
                "{\"local_addr\":\"%s\",\"local_port\":%d,\"remote_addr\":\"%s\",\"remote_port\":%d,\"state\":\"%s\",\"protocol\":\"%s\"}",
                e->detail.net_conn.local_addr, e->detail.net_conn.local_port,
                e->detail.net_conn.remote_addr, e->detail.net_conn.remote_port,
                e->detail.net_conn.state, e->detail.net_conn.protocol);
            break;
        }
        case EVENT_FILE_MODIFIED:
        {
            char path_esc[512];
            json_escape(e->detail.file_modfd.path, path_esc, sizeof(path_esc));

            char size_before_part[64] = "";
            char size_after_part[64] = "";
            if (e->detail.file_modfd.has_size_before)
                snprintf(size_before_part, sizeof(size_before_part), ",\"size_before\":%d", e->detail.file_modfd.size_before);
            if (e->detail.file_modfd.has_size_after)
                snprintf(size_after_part, sizeof(size_after_part), ",\"size_after\":%d", e->detail.file_modfd.size_after);

            snprintf(detail_buf, sizeof(detail_buf),
                "{\"path\":\"%s\",\"old_hash\":\"%s\",\"new_hash\":\"%s\"%s%s}",
                path_esc, e->detail.file_modfd.old_hash, e->detail.file_modfd.new_hash,
                size_before_part, size_after_part);
            break;
        }
        case EVENT_PRIVILEGE_CHANGE:
        {
            snprintf(detail_buf, sizeof(detail_buf),
                "{\"old_uid\":%d,\"new_uid\":%d,\"old_euid\":%d,\"new_euid\":%d,\"trigger\":\"%s\"}",
                e->detail.prev_chng.old_uid, e->detail.prev_chng.new_uid,
                e->detail.prev_chng.old_euid, e->detail.prev_chng.new_euid,
                TRIGGER_NAMES[e->detail.prev_chng.trigger]);
            break;
        }
        default:
            detail_buf[0] = '{'; detail_buf[1] = '}'; detail_buf[2] = '\0';
    }

    int n = snprintf(buf, buf_size,
        "{\"event_id\":\"%s\",\"timestamp\":\"%s\",\"event_type\":\"%s\","
        "\"source\":{\"pid\":%d,\"ppid\":%d,\"uid\":%d,\"euid\":%d,\"cmdline\":\"%s\",\"exe_path\":\"%s\"},"
        "\"detail\":%s}\n",
        e->event_id, e->timestamp, EVENT_TYPE_NAMES[e->event_type],
        e->source.pid, e->source.ppid, e->source.uid, e->source.euid,
        cmdline_esc, exe_esc, detail_buf);

    if (n < 0 || (size_t)n >= buf_size)
        return -1;
    return n;
}

void emit_event(EventEmitter *emitter, const event_t *e)
{
    char json_buf[2048];
    int len = build_json(e, json_buf, sizeof(json_buf));
    if (len < 0)
        return;

    if (emitter->log_file)
    {
        fwrite(json_buf, 1, len, emitter->log_file);
        fflush(emitter->log_file);
    }

    if (emitter->sock_fd < 0)
    {
        emitter->sock_fd = try_connect_socket(emitter->sock_path);
    }

    if (emitter->sock_fd >= 0)
    {
        ssize_t sent = send(emitter->sock_fd, json_buf, len, MSG_NOSIGNAL);
        if (sent < 0)
        {
            close(emitter->sock_fd);
            emitter->sock_fd = -1;
        }
    }
}

void event_emitter_destroy(EventEmitter *emitter)
{
    if (emitter->log_file)
        fclose(emitter->log_file);
    if (emitter->sock_fd >= 0)
        close(emitter->sock_fd);
}