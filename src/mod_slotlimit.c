/*
 * 
 * Date:        2011/04/10
 * Info:        mod_slotlimit Apache2 module
 * Contact:     mailto: <luca@lucaercoli.it>
 * Version:     1.3 
 * Author: 	Luca Ercoli
 *
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
 */


#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_main.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "apr_strings.h"
#include "scoreboard.h"
#include <string.h>

//Scoreboard only stores 32
#define VHOST_LEN     32 

#define MODULE_NAME "mod_slotlimit"
#define MODULE_VERSION "1.3"

module AP_MODULE_DECLARE_DATA slotlimit_module;

static int server_limit, thread_limit;

typedef struct {
    int conn_num;
    int site_conn_num;
    int perc_slots_available;
    char *errore;
    int client_ip;
    int is_set_vhost;
} mod_config;


static mod_config *create_config(apr_pool_t *p)
{
    mod_config *cfg = (mod_config *)
        apr_pcalloc(p, sizeof (*cfg));

    cfg->conn_num = 65432;
    cfg->site_conn_num = 65432;
    cfg->perc_slots_available = 13;
    cfg->client_ip=35;
    cfg->errore="Blocked by mod_slotlimit. More information about this error may be available in the server error log.";
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
    //Abort on subrequests
    if (!ap_is_initial_req(r))
    {
        return DECLINED;
    }

    mod_config *cfg = (mod_config *)
        ap_get_module_config(r->per_dir_config, &slotlimit_module);

    int clientip_count = 0;
    int vhost_count = 0;
    worker_score *ws_record;
    int busy_count = 0;
    int busy_max=0;
    int server_index;
    int thread_index;
    char *host;
    char *subhost;

    //Update vhost name in scoreboard if enabled
    if (cfg->is_set_vhost)
{
        host=apr_pstrndup(r->pool, apr_table_get(r->headers_in,"Host"), VHOST_LEN-1);
        if (host)
{
            //Strip www.
            subhost=host;
            while ( *subhost == 'w' ){
                subhost++;
            }
            if ((subhost-host == 3) && (*subhost == '.')){
                subhost++;
            }else{
                subhost=host;
            }
            r->server->server_hostname = subhost;
            conn_rec *c = r->connection;
            ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, r);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Vhost name set to %s", subhost);
        }
    }

    //Parse current scoreboard for busy slots
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Server limit %d, Thread limit %d", server_limit, thread_limit);
    for (server_index = 0; server_index < server_limit; ++server_index)
{
        for (thread_index = 0; thread_index < thread_limit; ++thread_index)
{
            ws_record = ap_get_scoreboard_worker(server_index, thread_index);
            switch (ws_record->status)
{
                case SERVER_BUSY_WRITE:
                case SERVER_BUSY_KEEPALIVE:
                case SERVER_BUSY_LOG:
                case SERVER_BUSY_DNS:
                case SERVER_CLOSING:
                case SERVER_GRACEFUL:
                    if (strcmp(r->server->server_hostname, ws_record->vhost) == 0) vhost_count++;
                case SERVER_BUSY_READ:
                    if (strcmp(r->connection->remote_ip,ws_record->client) == 0) clientip_count++;
                    busy_count++;
                    break;
                default:
                    break;
            }
        }
    }

    //Activate if above trigger level
    busy_max=(cfg->conn_num-((cfg->conn_num*cfg->perc_slots_available)/100));
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Site:%d IP:%d Total:%d Trigger:%d Max:%d", vhost_count, clientip_count, busy_count, busy_max, cfg->conn_num);
    if( busy_count >= busy_max){
        //Reject too many connections for site
        if ( (vhost_count > cfg->site_conn_num) ){
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
                    "mod_slotlimit: Host %s reached MaxConnectionsPerSite (%d)",r->hostname,cfg->site_conn_num);
            ap_custom_response(r, HTTP_SERVICE_UNAVAILABLE, cfg->errore);
            return HTTP_SERVICE_UNAVAILABLE;
        }
        //Reject too manay connections from ip
        if (clientip_count > cfg->client_ip){
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
                    "mod_slotlimit: Client %s reached ClientIpLimit (%d) Site: %s",r->connection->remote_ip,cfg->client_ip,r->hostname);
            ap_custom_response(r, HTTP_SERVICE_UNAVAILABLE, cfg->errore);
            return HTTP_SERVICE_UNAVAILABLE;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Protection active, no limit hit");
    }
    return DECLINED;
}


static const char *limit_cmd_max_clients(cmd_parms *parms, void *dummy, char *arg)
{

    mod_config *cfg = (mod_config *)dummy; 

    int num_req = atoi (arg);
    cfg->conn_num = num_req; 
    return NULL;
}

static const char *limit_cmd_max_connections_per_site(cmd_parms *parms, void *dummy, char *arg)
{

    mod_config *cfg = (mod_config *)dummy;

    int num_req = atoi (arg);
    cfg->site_conn_num = num_req;
    return NULL;
}



static const char *limit_cmd_available_slots_percent(cmd_parms *parms, void *dummy, char *arg)
{

    mod_config *cfg = (mod_config *)dummy;

    int num_req = atoi (arg);
    cfg->perc_slots_available = num_req;
    return NULL;
}


static const char *limit_cmd_custom_err_msg(cmd_parms *parms, void *dummy, char *arg)
{

    mod_config *cfg = (mod_config *)dummy;

    char *ops = arg;
    cfg->errore = ops;
    return NULL;
}


static const char *limit_cmd_client_ip_limit(cmd_parms *parms, void *dummy, char *arg)
{

    mod_config *cfg = (mod_config *)dummy;

    int num_req = atoi (arg);
    cfg->client_ip = num_req;
    return NULL;
}



static const char *limit_cmd_force_vhost_name(cmd_parms *cmd, void *dummy, int arg)
{

    mod_config *cfg = (mod_config *)dummy;


    cfg->is_set_vhost = arg;
    return NULL;
}



static command_rec slotlimit_cmds[] = {

    AP_INIT_TAKE1("MaxClients", (const char *(*)())limit_cmd_max_clients, NULL, RSRC_CONF,"Apache maxclient setting"),
    AP_INIT_TAKE1("AvailableSlotsPercent", (const char *(*)())limit_cmd_available_slots_percent, NULL, RSRC_CONF,"Percentage of slots available in order to set any restrictions"),
    AP_INIT_TAKE1("MaxConnectionsPerSite", (const char *(*)())limit_cmd_max_connections_per_site, NULL, RSRC_CONF,"Max connections for each running site"),
    AP_INIT_TAKE1("ClientIpLimit", (const char *(*)())limit_cmd_client_ip_limit, NULL, RSRC_CONF,"Limit of simultaneous connection per IP"),
    AP_INIT_TAKE1("CustomErrMsg", (const char *(*)())limit_cmd_custom_err_msg, NULL, RSRC_CONF,"Custom error message"),
    AP_INIT_FLAG("ForceVhostName", limit_cmd_force_vhost_name, NULL, RSRC_CONF,"\"On\" to force vhost hostname in scoreboard, \"Off\" to disable"),
    {NULL}
};

static int slotlimit_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
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
    ap_hook_access_checker(slotlimit_handler,NULL,NULL,APR_HOOK_MIDDLE);

}


module AP_MODULE_DECLARE_DATA slotlimit_module = {
    STANDARD20_MODULE_STUFF,
    slotlimit_create_dir_config, /* create per-dir config structures */
    NULL,                       /* merge  per-dir    config structures */
    slotlimit_create_config,  /* create per-server config structures */
    NULL,                       /* merge  per-server config structures */
    slotlimit_cmds,           /* table of config file commands       */
    register_hooks
};
