/* 
	vpopmail shit auth
*/

#ifdef APACHE2
#define PCALLOC apr_pcalloc
#define SNPRINTF apr_snprintf
#define PSTRDUP apr_pstrdup
#else
#define PCALLOC ap_pcalloc
#define SNPRINTF ap_snprintf
#define PSTRDUP ap_pstrdup
#endif

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_log.h"
#include "vpopmail.h"
#include "vauth.h"


/*
 * structure to hold the configuration details for the request
 */
typedef struct
{
  int vpopmailAuthoritative;	/* are we authoritative? */
  int vpopmailClearPasswd;	/* clear password? */
}
vpopmail_auth_config_rec;


#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif


#ifdef APACHE2
static void *
create_vpopmail_auth_dir_config (apr_pool_t * p, char *d)
#else
static void *
create_vpopmail_auth_dir_config (pool * p, char *d)
#endif
{
  vpopmail_auth_config_rec *m =
    PCALLOC (p, sizeof (vpopmail_auth_config_rec));
  if (!m)
    return NULL;		/* failure to get memory is a bad thing */

  /* default values */
  m->vpopmailAuthoritative = FALSE;
  m->vpopmailClearPasswd = TRUE;
  return (void *) m;
}

#ifdef APACHE2
static command_rec vpopmail_auth_cmds[] = {
  AP_INIT_FLAG ("vpopmailAuthoritative", ap_set_flag_slot,
		(void *) APR_XtOffsetOf (vpopmail_auth_config_rec,
					 vpopmailAuthoritative),
		OR_AUTHCFG, "vpopmail lookup is authoritative if On"),

  AP_INIT_FLAG ("vpopmailClearPasswd", ap_set_flag_slot,
		(void *) APR_XtOffsetOf (vpopmail_auth_config_rec,
					 vpopmailClearPasswd),
		OR_AUTHCFG, "Are passwords are encrypted?"),
  {NULL}
};
#else
static command_rec vpopmail_auth_cmds[] = {

  {"vpopmailAuthoritative", ap_set_flag_slot,
   (void *) XtOffsetOf (vpopmail_auth_config_rec, vpopmailAuthoritative),
   OR_AUTHCFG, FLAG, "vpopmail lookup is authoritative if On"},

  {"vpopmailClearPasswd", ap_set_flag_slot,
   (void *) XtOffsetOf (vpopmail_auth_config_rec, vpopmailClearPasswd),
   OR_AUTHCFG, FLAG, "Are passwords are encrypted?"},
  {NULL}
};
#endif

module vpopmail_auth_module;

/*
 * Fetch and return password string from database for named user.
 * If we are in NoPasswd mode, returns user name instead.
 * If user or password not found, returns NULL
 */
static char * get_vpopmail_pw (request_rec * r, char *user, vpopmail_auth_config_rec * m)
{
  struct vqpasswd *vpw = (struct vqpasswd *)malloc(sizeof (vpw));
  char *pw = NULL;		/* password retrieved */
  int ulen;
  char *buf;
  char *luzer;
  char *domen;
 
  buf = (char *) malloc (strlen (user));
  memset (buf, 0x0, strlen (user));
  luzer = (char *) malloc(strlen(user));
  memset(luzer,0x0,strlen(user));
  domen = (char *) malloc(strlen(user));
  memset(domen,0x0,strlen(user));
  strncpy (buf, user, strlen (user));

  // brzi hack :)
  luzer = ap_pstrdup(r->pool,strtok (buf, "@"));
  domen = ap_pstrdup(r->pool,strtok (NULL, "@"));

#ifdef APACHE2
      ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "vpopmail ERROR: hmmm %s %s",luzer,domen);
#else
      ap_log_error (APLOG_MARK, APLOG_ERR, r->server, "vpopmail error: hmmm %s %s",luzer,domen);
#endif


  if((vpw = vauth_getpw( luzer, domen)) == NULL)
    {
#ifdef APACHE2
      ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "vpopmail ERROR: nesto %s %s",luzer,domen);
#else
      ap_log_error (APLOG_MARK, APLOG_ERR, r->server, "vpopmail error: nesto %s %s",luzer,domen);
#endif
      return NULL;
    }
  else
    {
      return vpw->pw_passwd;
    }

}


/*
 * callback from Apache to do the authentication of the user to his
 * password.
 */
static int
vpopmail_authenticate_basic_user (request_rec * r)
{
  int passwords_match = 1;
  char *user;
  vpopmail_auth_config_rec *sec =   (vpopmail_auth_config_rec *) ap_get_module_config (r->per_dir_config,
								&vpopmail_auth_module);
  conn_rec *c = r->connection;
  const char *sent_pw, *real_pw;
  int res;
  if ((res = ap_get_basic_auth_pw (r, &sent_pw)))
    return res;
#ifdef APACHE2
      ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "vpopmail ERROR: vpopmail_authenticate_basic_user",);
#else
      ap_log_error (APLOG_MARK, APLOG_ERR, r->server, "vpopmail error: vpopmail_authenticate_basic_user");
#endif
  if (!sec->vpopmailAuthoritative)	/* not configured for vpopmail authorization */
    return DECLINED;

#ifdef APACHE2
  user = r->user;
#else
  user = c->user;
#endif
  if (!(real_pw = get_vpopmail_pw (r, user, sec)))
    {
      /* user not found in database */
      if (!sec->vpopmailAuthoritative)
	return DECLINED;	/* let other schemes find user */

#ifdef APACHE2
      ap_log_rerror (APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r,
		     "vpopmail user %s not found: %s", user, r->uri);
#else
      ap_log_error (APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r->server,
		    "vpopmail user %s not found: %s", user, r->uri);
#endif
      ap_note_basic_auth_failure (r);
#ifdef APACHE2
      return HTTP_UNAUTHORIZED;
#else
      return AUTH_REQUIRED;
#endif
    }


  /* if vpopmailClearPasswd is On, compare the scrambled password */
	if (strcmp
	(real_pw, sec->vpopmailClearPasswd ? crypt (sent_pw, real_pw) : sent_pw)) {
		passwords_match = TRUE;
	}

  if (passwords_match == TRUE)
    {
      return OK;
    }
  else
    {
#ifdef APACHE2
      ap_log_rerror (APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r,
		     "user %s: password mismatch: %s %s %s=%s", user, r->uri,sent_pw, real_pw);
#else
      ap_log_error (APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r->server,
		    "user %s: password mismatch: %s %s %s=%s", user, r->uri,sent_pw, real_pw);
#endif
      ap_note_basic_auth_failure (r);
#ifdef APACHE2
      return HTTP_UNAUTHORIZED;
#else
      return AUTH_REQUIRED;
#endif
    }
}


#ifdef APACHE2
static void
register_hooks (apr_pool_t * p)
{
  ap_hook_check_user_id (vpopmail_authenticate_basic_user, NULL, NULL,
			 APR_HOOK_MIDDLE);
  ap_hook_auth_checker (vpopmail_check_auth, NULL, NULL, APR_HOOK_MIDDLE);
}
#endif

#ifdef APACHE2
module AP_MODULE_DECLARE_DATA vpopmail_auth_module = {
  STANDARD20_MODULE_STUFF,
  create_vpopmail_auth_dir_config,	/* dir config creater */
  NULL,				/* dir merger --- default is to override */
  NULL,				/* server config */
  NULL,				/* merge server config */
  vpopmail_auth_cmds,		/* command apr_table_t */
  register_hooks		/* register hooks */
};
#else
module vpopmail_auth_module = {
  STANDARD_MODULE_STUFF,
  NULL,				/* initializer */
  create_vpopmail_auth_dir_config,	/* dir config creater */
  NULL,				/* dir merger --- default is to override */
  NULL,				/* server config */
  NULL,				/* merge server config */
  vpopmail_auth_cmds,		/* command table */
  NULL,				/* handlers */
  NULL,				/* filename translation */
  vpopmail_authenticate_basic_user,	/* check_user_id */
  NULL,				/* check auth */
  NULL,				/* check access */
  NULL,				/* type_checker */
  NULL,				/* fixups */
  NULL,				/* logger */
  NULL,				/* header parser */
  NULL,				/* child_init */
  NULL,				/* child_exit */
  NULL				/* post read-request */
};
#endif
