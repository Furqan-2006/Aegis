#pragma once

#include "event_schema.h"

typedef struct
{
    char path[256];
    char last_hash[65];
    long last_size;
} watched_file_t;

typedef struct
{
    watched_file_t *files;
    int count;
    int cap;
} FileIntegrityState;

void file_integrity_init(FileIntegrityState *state, const char **paths, int path_count);
void file_integrity_destroy(FileIntegrityState *state);

int check_watched_files(FileIntegrityState *state, event_t **out_events, int *out_count);