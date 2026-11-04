/* hub_uhist.h - upgrade history, see hub_uhist.c */
#ifndef HUB_UHIST_H
#define HUB_UHIST_H

#include "hub.h"
#include "hub_reply.h"

bool hub_uhist_parse(const char *body, uhist_view_t *v);
bool hub_uhist_format(const uhist_view_t *v, char *out, size_t cap);
void hub_uhist_view_free(uhist_view_t *v);
int  hub_uhist_keep(const hub_state_t *state);
void hub_uhist_trim(hub_state_t *state);
int  hub_uhist_find(const hub_state_t *state, const char *id);
bool hub_uhist_load_line(hub_state_t *state, const char *body);
void hub_uhist_send_digest(hub_state_t *state, hub_client_t *c);
void hub_uhist_process(hub_state_t *state, hub_client_t *from, const char *payload);
void hub_uhist_put_own(hub_state_t *state, uhist_view_t *v);
void hub_uhist_plan_by(const hub_state_t *state, long long plan_id, char *out, size_t cap);
void hub_uhist_boot(hub_state_t *state);
void hub_uhist_reply_runs(const hub_state_t *state, reply_t *r);
int  hub_uhist_reply_one(const hub_state_t *state, const char *pfx, reply_t *r);

#endif
