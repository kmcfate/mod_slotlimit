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

#define VHOST_LEN     32 

#define MODULE_NAME "mod_slotlimit"
#define MODULE_VERSION "1.3"

#define RULES_SIZE      512
#define COLONNALEN      256

module AP_MODULE_DECLARE_DATA slotlimit_module;

static void *slotlimit_create_config(apr_pool_t *p, server_rec *s);
static void *slotlimit_create_dir_config(apr_pool_t *p, char *path);
static int slotlimit_handler(request_rec *r);
static const char *limit_config_cmd(cmd_parms *parms, void *dummy,char arg[]);
static const char *limit_config2_cmd(cmd_parms *parms, void *dummy,char arg[]);
static const char *limit_config3_cmd(cmd_parms *parms, void *dummy,char arg[]);
static const char *limit_config5_cmd(cmd_parms *parms, void *dummy,char arg[]);
static const char *force_vhost_name(cmd_parms *cmd, void *dummy, int arg);
static int slotlimit_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
static void register_hooks(apr_pool_t *p);
void listadomini(char *file);

char temp[VHOST_LEN];

static int server_limit, thread_limit;

char listasporca[RULES_SIZE][COLONNALEN];
char nome_dominio[RULES_SIZE][COLONNALEN];
int  numero_connessioni[RULES_SIZE];
int  numero_connessioni_attuali[RULES_SIZE];

typedef struct {
	int conn_num;
	int site_conn_num;
	int perc_slots_available;
	char *errore;
	int client_ip;
	int is_set_vhost;
	char *rules;
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
	cfg->rules="NoCustomRules";
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


void listadomini(char *file)
{

    int count = 0;

    char *token;
    FILE *effeppi;

    for (count; count < RULES_SIZE; count++) memset(listasporca[count],'\0',COLONNALEN);
    count = 0;

    for (count; count < RULES_SIZE; count++) memset(nome_dominio[count],'\0',COLONNALEN);
    count = 0;

    for (count; count < RULES_SIZE; count++) numero_connessioni_attuali[count]=0;
    count = 0;


    effeppi = fopen(file,"r");

    if(effeppi)
    {
	while (!feof(effeppi))
	{
	    if (count < RULES_SIZE)
	    {
		fgets(listasporca[count], COLONNALEN, effeppi);
		count++;
		
		if (strstr(listasporca[count-1],"#") != NULL)
		{
		count--;
	 	memset(listasporca[count],'\0',COLONNALEN);	
		}
	
	    }

	    else break;
	}
	fclose(effeppi);
    }

    count = 0;
    for (count; count < RULES_SIZE; count++)
    {
	token = strtok (listasporca[count]," ");
	if (token != NULL)
	{
	    strncpy(nome_dominio[count],token,COLONNALEN);
	}
	token = strtok (NULL, "\n");
	if (token != NULL)
	{
	    numero_connessioni[count]=atoi(token);
	}

    }

}

static int core(request_rec *r, mod_config *cfg)
{

	if (!ap_is_initial_req(r))
	{
		return DECLINED;
	}


	int i;
	int j;

	int rx;

	int clientip_count = 0;
	int vhost_count = 0;
	int nAllSlots = 0;        

	char siti_visitati[2048][VHOST_LEN];

	worker_score *ws_record;
	
	char myrhostname[256];
	memset(myrhostname,'\0',256);


	if (cfg->is_set_vhost)
	{
		ws_record = ap_get_scoreboard_worker(r->connection->id, 0);

		/*
		 * function ap_update_child_status (defined in server/scoreboard.c) overwrite ws->vhost
		 *
		 */
		/* According to RFC 2616, Host header field CAN be blank. */	


	if ( apr_table_get(r->headers_in,"Host"))
	{
	memset(temp,'\0',VHOST_LEN);
	strncpy(temp,apr_table_get(r->headers_in,"Host"),VHOST_LEN);

	r->server->server_hostname = &temp;
	
	conn_rec *c = r->connection;
	(void)ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, r);

	}


	}




	for (i = 0; i < server_limit; ++i) {
		for (j = 0; j < thread_limit; ++j) {
			ws_record = ap_get_scoreboard_worker(i, j);
			switch (ws_record->status) {
				case SERVER_BUSY_READ:
				case SERVER_BUSY_WRITE:
				case SERVER_BUSY_KEEPALIVE:
				//case SERVER_BUSY_LOG:
				//case SERVER_BUSY_DNS:


					strncpy(siti_visitati[nAllSlots],ws_record->vhost,VHOST_LEN);

					nAllSlots++;


					if ( (strcmp(r->server->server_hostname, ws_record->vhost) == 0)  ) vhost_count++;

					if (strcmp(r->connection->remote_ip,ws_record->client) == 0) clientip_count++;

					for(rx=0; rx < RULES_SIZE; rx++)
					{
					    if (strcmp (nome_dominio[rx],ws_record->vhost) == 0) numero_connessioni_attuali[rx]++;
					}


					break;

				default:
					break;
			}
		}
	}


	snprintf(myrhostname,256,"%s",r->hostname);

	for(rx=0; rx < RULES_SIZE; rx++)
	{
	    if (strcmp (nome_dominio[rx],myrhostname) == 0) {
		if (numero_connessioni_attuali[rx] > numero_connessioni[rx]){
		    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,"mod_slotlimit: Host %s reached his MaxClients (%d)",myrhostname,numero_connessioni[rx]);
		    ap_custom_response(r, HTTP_NOT_ACCEPTABLE, cfg->errore);
		    for (i=0; i < RULES_SIZE; i++)numero_connessioni_attuali[i]=0;
		    return HTTP_NOT_ACCEPTABLE;
		}
		else {
		    for (i=0; i < RULES_SIZE; i++)numero_connessioni_attuali[i]=0;
		    return DECLINED;
		}
	    }
	}


	if ( (vhost_count > cfg->site_conn_num) ){
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
				"mod_slotlimit: Host %s reached MaxConnectionsPerSite (%d)",r->hostname,cfg->site_conn_num);
		ap_custom_response(r, HTTP_NOT_ACCEPTABLE, cfg->errore);
		return HTTP_NOT_ACCEPTABLE;
	}



	if (clientip_count > cfg->client_ip){

		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
				"mod_slotlimit: Client %s reached ClientIpLimit (%d) Site: %s",r->connection->remote_ip,cfg->client_ip,r->hostname);
		ap_custom_response(r, HTTP_NOT_ACCEPTABLE, cfg->errore);
		return HTTP_NOT_ACCEPTABLE;

	}



	if ( (cfg->perc_slots_available > 0) && (nAllSlots >= (cfg->conn_num - ( (cfg->conn_num * cfg->perc_slots_available) / 100))) ){	


		qsort ( (char *)siti_visitati, nAllSlots, sizeof (*siti_visitati), strcmp);

		j = 0;
		i = 0;

		for (i; i < nAllSlots ; i++)  if (strcmp(siti_visitati[i+1],siti_visitati[i])) j++;


		if ( vhost_count >= ( (cfg->conn_num / j) + (cfg->conn_num - nAllSlots)  ) ){

			ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "mod_slotlimit: SiteName: %s  SlotsUsed: %d  LimitTo %d",r->hostname,vhost_count,((cfg->conn_num / j) + (cfg->conn_num - nAllSlots)) );

			ap_custom_response(r, HTTP_NOT_ACCEPTABLE, cfg->errore);
			return HTTP_NOT_ACCEPTABLE;
		} 

	}

	return DECLINED;
}


static int slotlimit_handler(request_rec *r)
{
	mod_config *cfg = (mod_config *)
		ap_get_module_config(r->per_dir_config, &slotlimit_module);

	int result;

	result = core(r, cfg);

	return result;
}


static const char *limit_config_cmd(cmd_parms *parms, void *dummy,
		char arg[])
{

	mod_config *cfg = (mod_config *)dummy; 
	ap_get_module_config(parms->server->module_config, &slotlimit_module);

	int num_req = atoi (arg);
	cfg->conn_num = num_req; 
	return NULL;
}

static const char *limit_lastconfig_cmd(cmd_parms *parms, void *dummy,
	char *arg)
{

    mod_config *cfg = (mod_config *)dummy;
    ap_get_module_config(parms->server->module_config, &slotlimit_module);

    cfg->rules = (char *)arg;

    listadomini(cfg->rules);

    return NULL;
}

static const char *limit_config2_cmd(cmd_parms *parms, void *dummy,
		char arg[])
{

	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(parms->server->module_config, &slotlimit_module);

	int num_req = atoi (arg);
	cfg->site_conn_num = num_req;
	return NULL;
}



static const char *limit_config3_cmd(cmd_parms *parms, void *dummy,
		char arg[])
{

	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(parms->server->module_config, &slotlimit_module);

	int num_req = atoi (arg);
	cfg->perc_slots_available = num_req;
	return NULL;
}


static const char *limit_config7_cmd(cmd_parms *parms, void *dummy,
                char *arg)
{

        mod_config *cfg = (mod_config *)dummy;
        ap_get_module_config(parms->server->module_config, &slotlimit_module);

        char *ops = arg;
        cfg->errore = ops;
        return NULL;
}


static const char *limit_config5_cmd(cmd_parms *parms, void *dummy,
		char arg[])
{

	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(parms->server->module_config, &slotlimit_module);

	int num_req = atoi (arg);
	cfg->client_ip = num_req;
	return NULL;
}



static const char *force_vhost_name(cmd_parms *cmd, void *dummy, int arg)
{
	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
	if (err != NULL) {
		return err;
	}

	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(cmd->server->module_config, &slotlimit_module);


	cfg->is_set_vhost = arg;
	return NULL;
}



static command_rec slotlimit_cmds[] = {

	AP_INIT_TAKE1("MaxClients", limit_config_cmd, NULL, RSRC_CONF,"Apache maxclient setting"),
	AP_INIT_TAKE1("AvailableSlotsPercent", limit_config3_cmd, NULL, RSRC_CONF,"Percentage of slots available in order to set any restrictions"),
	AP_INIT_TAKE1("MaxConnectionsPerSite", limit_config2_cmd, NULL, RSRC_CONF,"Max connections for each running site"),
	AP_INIT_TAKE1("ClientIpLimit", limit_config5_cmd, NULL, RSRC_CONF,"Limit of simultaneous connection per IP"),
	AP_INIT_TAKE1("CustomErrMsg", limit_config7_cmd, NULL, RSRC_CONF,"Custom error message"),
	AP_INIT_FLAG("ForceVhostName", force_vhost_name, NULL, RSRC_CONF,"\"On\" to force vhost hostname in scoreboard, \"Off\" to disable"),
	AP_INIT_TAKE1("CustomLimitsFile", limit_lastconfig_cmd, NULL, RSRC_CONF,"Write here custom per-site limit. Format: \"SiteName NumberOfSlots\""),
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
