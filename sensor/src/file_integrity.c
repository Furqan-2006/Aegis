#define __GNU_SOURCE

#include "../include/file_integrity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/evp.h>

static int compute_sha256(const char *path, char *out_hash, long *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    unsigned char buf[8192];
    size_t n;
    long total = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    {
        EVP_DigestUpdate(ctx, buf, n);
        total += n;
    }
    fclose(f);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_DigestFinal_ex(ctx, digest, &digest_len);

    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < digest_len; i++)
    {
        snprintf(out_hash + (i * 2), "%02x", digest[i]);
    }
    out_hash[digest_len * 2] = '\0';

    *out_size = total;
    return 0;
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

void file_integrity_init(FileIntegrityState *state, const char **paths, int path_count)
{
    state->cap = path_count > 0 ? path_count : 4;
    state->count = 0;
    state->files = malloc(state->cap * sizeof(watched_file_t));

    for (int i = 0; i < path_count; i++)
    {
        watched_file_t *wf = &state->files[state->count];
        strncpy(wf->path, paths[i], sizeof(wf->path) - 1);
        wf->path[sizeof(wf->path) - 1] = '\0';

        char hash[65];
        long size;
        if (compute_sha256(paths[i], hash, &size) == 0)
        {
            strcpy(wf->last_hash, hash);
            wf->last_size = size;
        }
        else
        {
            wf->last_hash[0] = '\0'; // unreadable at startup; treat as "no baseline"
            wf->last_size = -1;
        }
        state->count++;
    }
}

void file_integrity_destroy(FileIntegrityState *state)
{
    free(state->files);
    state->files = NULL;
    state->count = 0;
    state->cap = 0;
}

int check_watched_files(FileIntegrityState *state, event_t **out_events, int *out_count)
{
    int events_cap = 4;
    int events_count = 0;
    event_t *events = malloc(events_cap * sizeof(event_t));

    for (int i = 0; i < state->count; i++)
    {
        watched_file_t *wf = &state->files[i];

        char new_hash[65];
        long new_size;
        if (compute_sha256(wf->path, new_hash, &new_size) != 0)
            continue; // file unreadable this cycle — skip, don't crash

        if (wf->last_hash[0] != '\0' && strcmp(wf->last_hash, new_hash) != 0)
        {
            ensure_event_capacity(&events, &events_cap, events_count);
            event_t *e = &events[events_count++];
            fill_common_fields(e, EVENT_FILE_MODIFIED);

            // source process responsible for the change isn't directly knowable
            // from a hash diff alone; left zeroed. (Known limitation — flagged.)
            strncpy(e->detail.file_modfd.path, wf->path, sizeof(e->detail.file_modfd.path) - 1);
            strncpy(e->detail.file_modfd.old_hash, wf->last_hash, sizeof(e->detail.file_modfd.old_hash) - 1);
            strncpy(e->detail.file_modfd.new_hash, new_hash, sizeof(e->detail.file_modfd.new_hash) - 1);
            e->detail.file_modfd.size_before = (int)wf->last_size;
            e->detail.file_modfd.has_size_before = true;
            e->detail.file_modfd.size_after = (int)new_size;
            e->detail.file_modfd.has_size_after = true;
        }

        strcpy(wf->last_hash, new_hash);
        wf->last_size = new_size;
    }

    *out_events = events;
    *out_count = events_count;
    return 0;
}
