#pragma once

#include "event_schema.h"
#include <stdio.h>

typedef struct {
    FILE *log_file;
    int sock_fd;
    char sock_path[108];
} EventEmitter;

int event_emitter_init(EventEmitter *emitter, const char *log_path, const char *sock_path);
void event_emitter_destroy(EventEmitter *emitter);
void emit_event(EventEmitter *emitter, const event_t *e);