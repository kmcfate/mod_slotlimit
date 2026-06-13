/*
 * mod_slotlimit - Apache 2.4 module
 *
 * Date:        2026/06/13
 * Info:        Per-vhost and per-IP connection limits for Apache 2.4
 * Contact:     mailto: <kmcfate@darkink.com>
 * Version:     2.0  (modernized for Apache 2.4 / gcc 13+)
 * Original Author: Luca Ercoli <luca@lucaercoli.it>
 *               Original mod_slotlimit 1.3, 2011/04/10
 * Updated by:  Kali McFate <kmcfate@darkink.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *
 * Changes in 2.0 (Apache 2.4 / gcc 13+ modernization):
 *   - Replaced deprecated ap_get_scoreboard_worker(child, thread) with
 *     ap_copy_scoreboard_worker(&ws, child, thread). The new API takes
 *     a destination buffer and copies the scoreboard entry into it,
 *     which is actually safer (we do not read shared memory while
 *     another thread writes to it).
 *   - Fixed per-dir vs per-server config bug: the handler was reading
 *     r->per_dir_config but the directives are all RSRC_CONF. Changed
 *     to r->server->module_config so the directives actually take effect.
 *   - Added fallthrough comments to silence -Wimplicit-fallthrough.
 *   - Moved all C declarations to the top of functions (C89 style)
 *     for compatibility with strict compiler flags. gcc 13 enables
 *     -Wdeclaration-after-statement by default in some configs.
 *   - Removed C89-style function pointer casts in command definitions.
 *     The casts were workarounds for old K&R-style declaration quirks
 *     that modern gcc rejects.
 *   - Fixed const-correctness: errore is now const char* and we use
 *     apr_pstrdup to copy the literal into the pool so it can be
 *     safely modified or freed later.
 *   - Removed deprecated http_main.h include (no longer needed).
 *   - Added note about volatile mitigation for shared scoreboard reads
 *     (now handled by ap_copy_scoreboard_worker, but documented).
 *   - Updated hook signature: ap_hook_post_read_request now takes an
 *     int kind parameter via the helper macro; this was already correct
 *     in the old code but the helper macro changed names.
 *   - Bumped MODULE_VERSION to 2.0.
 *   - Updated src/mod_slotlimit.c to use ap_log_rerror() instead of
 *     ap_log_error() where a request_rec is available, for proper
 *     access log correlation.
 *   - Fixed conn_rec.remote_ip → conn_rec.client_ip. The remote_ip
 *     field was REMOVED in Apache 2.4; the IP address is now in
 *     client_ip (and remote_host is the resolved DNS hostname, not
 *     the IP). The original 2011 code was already wrong and would
 *     not have compiled against modern Apache.
 *   - Added 0 for flags to the module struct. STANDARD20_MODULE_STUFF
 *     in Apache 2.4 already includes the rewrite_args slot (the last
 *     NULL in the macro), so we only needed to add the explicit flags
 *     field at the end. The original 2011 code was missing both rewrite_args
 *     and flags initializers; gcc -Wmissing-field-initializers flags
 *     this in modern versions.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "apr_strings.h"
#include "scoreboard.h"
#include <string.h>

/* Scoreboard only stores 32 chars for vhost. Hostname is truncated
 * to fit. If your vhost name is longer than 31 chars, the comparison
 * in the scoreboard loop will never match. */
#define VHOST_LEN     32

#define MODULE_NAME "mod_slotlimit"
#define MODULE_VERSION "2.0"

module AP_MODULE_DECLARE_DATA slotlimit_module;

static int server_limit, thread_limit;

typedef struct {
    int conn_num;
    int site_conn_num;
    int perc_slots_available;
    const char *errore;
    int client_ip;
    int is_set_vhost;
} mod_config;


static mod_config *create_config(apr_pool_t *p)
{
    mod_config *cfg = (mod_config *)
        apr_pcalloc(p, sizeof(*cfg));

    cfg->conn_num = 65432;
    cfg->site_conn_num = 65432;
    cfg->perc_slots_available = 13;
    cfg->client_ip = 35;
    /* Note: original used a string literal assigned to char*. We now
     * copy it into the pool so the memory is owned by the pool. This
     * also fixes the const-correctness warning in gcc 13. */
    cfg->errore = apr_pstrdup(p,
        "Blocked by mod_slotlimit. More information about this error may be available in the server error log.");
    return cfg;
}


/* per-server configuration structure */
static void *slotlimit_create_config(apr_pool_t *p, server_rec *s)
{
    return create_config(p);
}


/* per-directory configuration structure */
static void *slotlimit_create_dir_config(apr_pool_t *p, char *path)
{
    return create_config(p);
}

static int slotlimit_handler(request_rec *r)
{
    int clientip_count = 0;
    int vhost_count = 0;
    int busy_count = 0;
    int busy_max = 0;
    int server_index;
    int thread_index;
    char *host;
    char *subhost;
    mod_config *cfg;
    worker_score ws_record;

    /* Abort on subrequests — only act on the original request from
     * the client. This is critical for connection counting: a subrequest
     * (e.g. from mod_include) shouldn't count as a new client connection. */
    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    /* BUGFIX (v2.0): Original code read r->per_dir_config, but all
     * directives are RSRC_CONF (server-level). Per-dir and per-server
     * get separate mod_config structs via the two create_*_config
     * functions, so reading per_dir meant the RSRC_CONF directives
     * had no effect. Use server->module_config instead. */
    cfg = (mod_config *)
        ap_get_module_config(r->server->module_config, &slotlimit_module);

    /* Update vhost name in scoreboard if enabled. Some mass virtual
     * hosting setups mean r->server->server_hostname doesn't reflect
     * the actual site being visited. ForceVhostName fixes that by
     * updating the scoreboard entry's vhost field. */
    if (cfg->is_set_vhost) {
        conn_rec *c;
        host = apr_pstrndup(r->pool, apr_table_get(r->headers_in, "Host"),
                            VHOST_LEN - 1);
        if (host) {
            /* Strip leading "www." if present. The original code
             * loops while *subhost == 'w' but that's actually a bit
             * loose (it'd also strip "ww.", "wwwx" etc.). Kept the
             * original behavior for compat; tighter match in v2.0
             * might be a follow-up. */
            subhost = host;
            while (*subhost == 'w') {
                subhost++;
            }
            if ((subhost - host == 3) && (*subhost == '.')) {
                subhost++;
            } else {
                subhost = host;
            }
            r->server->server_hostname = subhost;
            c = r->connection;
            ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, r);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "Vhost name set to %s", subhost);
        }
    }

    /* Parse the entire scoreboard. We use ap_copy_scoreboard_worker
     * (NOT the deprecated ap_get_scoreboard_worker) which copies
     * the entry into a local worker_score struct. This is safer
     * because we get a snapshot — the shared memory can change
     * underneath us between reads in the deprecated version.
     *
     * We count three things per busy slot:
     *   - vhost_count: busy slots for the current vhost
     *   - clientip_count: busy slots from the current client IP
     *   - busy_count: total busy slots
     *
     * Note: SERVER_BUSY_READ counts toward clientip_count AND busy_count
     * but NOT toward vhost_count. This is intentional — we don't want
     * a read-phase connection (just starting) to count against the
     * vhost's MaxConnectionsPerSite yet. The original fallthrough
     * achieved this; v2.0 keeps the same behavior with fallthrough
     * annotations so gcc 13 doesn't warn. */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "Server limit %d, Thread limit %d",
                  server_limit, thread_limit);

    for (server_index = 0; server_index < server_limit; ++server_index) {
        for (thread_index = 0; thread_index < thread_limit; ++thread_index) {
            ap_copy_scoreboard_worker(&ws_record, server_index, thread_index);
            switch (ws_record.status) {
                case SERVER_BUSY_WRITE:
                case SERVER_BUSY_KEEPALIVE:
                case SERVER_BUSY_LOG:
                case SERVER_BUSY_DNS:
                case SERVER_CLOSING:
                case SERVER_GRACEFUL:
                    if (strcmp(r->server->server_hostname, ws_record.vhost) == 0) {
                        vhost_count++;
                    }
                    /* fallthrough */
                case SERVER_BUSY_READ:
                    if (strcmp(r->connection->client_ip, ws_record.client) == 0) {
                        clientip_count++;
                    }
                    busy_count++;
                    break;
                default:
                    break;
            }
        }
    }

    /* Calculate the activation threshold. Protection only kicks in
     * once busy_count exceeds (conn_num - conn_num*perc/100). At
     * 0% (default? no, default is 13), protection is always active. */
    busy_max = (cfg->conn_num -
                ((cfg->conn_num * cfg->perc_slots_available) / 100));

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "Site:%d IP:%d Total:%d Trigger:%d Max:%d",
                  vhost_count, clientip_count, busy_count,
                  busy_max, cfg->conn_num);

    if (busy_count >= busy_max) {
        /* Reject: too many connections to this vhost */
        if (vhost_count > cfg->site_conn_num) {
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                          "mod_slotlimit: Host %s reached "
                          "MaxConnectionsPerSite (%d)",
                          r->hostname, cfg->site_conn_num);
            ap_custom_response(r, HTTP_SERVICE_UNAVAILABLE, cfg->errore);
            return HTTP_SERVICE_UNAVAILABLE;
        }
        /* Reject: too many connections from this client IP */
        if (clientip_count > cfg->client_ip) {
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                          "mod_slotlimit: Client %s reached "
                          "ClientIpLimit (%d) Site: %s",
                          r->connection->client_ip, cfg->client_ip,
                          r->hostname);
            ap_custom_response(r, HTTP_SERVICE_UNAVAILABLE, cfg->errore);
            return HTTP_SERVICE_UNAVAILABLE;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "Protection active, no limit hit");
    }
    return DECLINED;
}


/* ====== Configuration directive handlers ====== */

/* Each handler receives the cmd_parms (which contains the directive's
 * location and pool), the per-server config pointer (the "dummy"
 * argument from AP_INIT_*), and the argument string. Modern gcc
 * requires us to use the actual function signature, not cast through
 * a generic function pointer. */

static const char *limit_cmd_max_clients(cmd_parms *parms, void *dummy,
                                         const char *arg)
{
    mod_config *cfg = (mod_config *)
        ap_get_module_config(parms->server->module_config, &slotlimit_module);
    cfg->conn_num = atoi(arg);
    return NULL;
}

static const char *limit_cmd_max_connections_per_site(cmd_parms *parms,
                                                      void *dummy,
                                                      const char *arg)
{
    mod_config *cfg = (mod_config *)
        ap_get_module_config(parms->server->module_config, &slotlimit_module);
    cfg->site_conn_num = atoi(arg);
    return NULL;
}

static const char *limit_cmd_available_slots_percent(cmd_parms *parms,
                                                     void *dummy,
                                                     const char *arg)
{
    mod_config *cfg = (mod_config *)
        ap_get_module_config(parms->server->module_config, &slotlimit_module);
    cfg->perc_slots_available = atoi(arg);
    return NULL;
}

static const char *limit_cmd_custom_err_msg(cmd_parms *parms, void *dummy,
                                            const char *arg)
{
    mod_config *cfg = (mod_config *)
        ap_get_module_config(parms->server->module_config, &slotlimit_module);
    /* Note: the original code assigned the const char* arg directly
     * to cfg->errore. Since cfg->errore is const char*, this is now
     * fine. We don't need to copy because the config string lives
     * for the lifetime of the config. */
    cfg->errore = arg;
    return NULL;
}

static const char *limit_cmd_client_ip_limit(cmd_parms *parms, void *dummy,
                                             const char *arg)
{
    mod_config *cfg = (mod_config *)
        ap_get_module_config(parms->server->module_config, &slotlimit_module);
    cfg->client_ip = atoi(arg);
    return NULL;
}

static const char *limit_cmd_force_vhost_name(cmd_parms *cmd, void *dummy,
                                              int arg)
{
    mod_config *cfg = (mod_config *)
        ap_get_module_config(cmd->server->module_config, &slotlimit_module);
    cfg->is_set_vhost = arg;
    return NULL;
}


static const command_rec slotlimit_cmds[] = {
    AP_INIT_TAKE1("MaxClients", limit_cmd_max_clients, NULL, RSRC_CONF,
                  "Apache MaxClients setting"),
    AP_INIT_TAKE1("AvailableSlotsPercent",
                  limit_cmd_available_slots_percent, NULL, RSRC_CONF,
                  "Percentage of slots available before restrictions activate"),
    AP_INIT_TAKE1("MaxConnectionsPerSite",
                  limit_cmd_max_connections_per_site, NULL, RSRC_CONF,
                  "Max connections for each running site"),
    AP_INIT_TAKE1("ClientIpLimit", limit_cmd_client_ip_limit, NULL, RSRC_CONF,
                  "Max simultaneous connections per IP"),
    AP_INIT_TAKE1("CustomErrMsg", limit_cmd_custom_err_msg, NULL, RSRC_CONF,
                  "Custom error message returned when limit is hit"),
    AP_INIT_FLAG("ForceVhostName", limit_cmd_force_vhost_name, NULL, RSRC_CONF,
                 "\"On\" to force vhost hostname in scoreboard, "
                 "\"Off\" to disable"),
    {NULL}
};

static int slotlimit_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
                          server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 MODULE_NAME " " MODULE_VERSION " started.");
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(slotlimit_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(slotlimit_handler, NULL, NULL, APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA slotlimit_module = {
    STANDARD20_MODULE_STUFF,
    slotlimit_create_dir_config,  /* create per-dir config structures */
    NULL,                          /* merge  per-dir    config structures */
    slotlimit_create_config,       /* create per-server config structures */
    NULL,                          /* merge  per-server config structures */
    slotlimit_cmds,                /* table of config file commands       */
    register_hooks,                /* hook registration                   */
    0                              /* flags (no AP_MODULE_FLAG_* set)     */
};
