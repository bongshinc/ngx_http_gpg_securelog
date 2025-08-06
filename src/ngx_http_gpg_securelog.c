#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <time.h>

#define DEFAULT_LOG_FILENAME NGX_ERROR_LOG_PATH

extern ngx_module_t ngx_http_gpg_securelog;

typedef enum {
    ROTATE_HOURLY,
    ROTATE_DAILY,
    ROTATE_WEEKLY,
    ROTATE_MONTHLY
} rotate_mode_t;

typedef struct {
    ngx_str_t log_path;
    ngx_str_t rotation_mode;
    ngx_str_t gpg_publickey_file;
} ngx_http_gpg_securelog_conf_t;

// === Get default log path (e.g., /usr/local/nginx/logs/securelog) ===
static const char *get_default_log_path(ngx_pool_t *pool) {
    char *log_path = ngx_pstrdup(pool, (u_char *)DEFAULT_LOG_FILENAME);
    if (!log_path) return NULL;

    char *dir = dirname(log_path);
    size_t len = strlen(dir) + sizeof("/securelog");
    char *full_path = ngx_palloc(pool, len);
    if (!full_path) return NULL;

    snprintf(full_path, len, "%s/securelog", dir);
    return full_path;
}

static ngx_int_t ngx_http_gpg_securelog_handler(ngx_http_request_t *r) {
    ngx_http_gpg_securelog_conf_t *conf = ngx_http_get_module_main_conf(r, ngx_http_gpg_securelog);
    if (conf->gpg_publickey_file.len == 0) {
        return NGX_OK;
    }

    const char *key_file = (char *)conf->gpg_publickey_file.data;

    const char *log_path = (conf->log_path.len > 0)
        ? (char *)conf->log_path.data
        : get_default_log_path(r->pool);

    if (!log_path) return NGX_OK;

    struct stat st = {0};
    if (stat(log_path, &st) == -1) {
        if (mkdir(log_path, 0700) == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "securelog: Failed to create log directory %s", log_path);
            return NGX_OK;
        }
    }

    ngx_str_t remote_addr = r->connection->addr_text;
    ngx_str_t method = r->method_name;
    ngx_str_t uri = r->uri;
    ngx_str_t user_agent = r->headers_in.user_agent ? r->headers_in.user_agent->value : ngx_string("-");

    time_t rawtime;
    struct tm *timeinfo;
    char date_buf[32], log_buf[1024], cmd_buf[4096];

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    rotate_mode_t mode = ROTATE_DAILY;
    if (conf->rotation_mode.len > 0) {
        if (ngx_strncmp(conf->rotation_mode.data, "hourly", 6) == 0) mode = ROTATE_HOURLY;
        else if (ngx_strncmp(conf->rotation_mode.data, "weekly", 6) == 0) mode = ROTATE_WEEKLY;
        else if (ngx_strncmp(conf->rotation_mode.data, "monthly", 7) == 0) mode = ROTATE_MONTHLY;
    }

    switch (mode) {
        case ROTATE_HOURLY:  strftime(date_buf, sizeof(date_buf), "%Y%m%d-%H00", timeinfo); break;
        case ROTATE_DAILY:   strftime(date_buf, sizeof(date_buf), "%Y%m%d-0000", timeinfo); break;
        case ROTATE_WEEKLY: {
            int week = timeinfo->tm_yday / 7 + 1;
            snprintf(date_buf, sizeof(date_buf), "%04dW%02d-0000", timeinfo->tm_year + 1900, week);
            break;
        }
        case ROTATE_MONTHLY: strftime(date_buf, sizeof(date_buf), "%Y%m-0000", timeinfo); break;
    }

    snprintf(log_buf, sizeof(log_buf),
             "%s [%s] \"%.*s %.*s\" \"%.*s\"\n",
             (char *)remote_addr.data, date_buf,
             (int)method.len, (char *)method.data,
             (int)uri.len, (char *)uri.data,
             (int)user_agent.len, (char *)user_agent.data);

    char gnupghome_template[] = "/tmp/nginx_gpg_XXXXXX";
    char *gnupghome = mkdtemp(gnupghome_template);
    if (!gnupghome) return NGX_OK;

    snprintf(cmd_buf, sizeof(cmd_buf),
             "export GNUPGHOME='%s' && "
             "gpg --quiet --batch --yes --no-default-keyring --keyring $GNUPGHOME/pubring.kbx "
             "--import '%s' && "
             "echo \"%s\" | gpg --quiet --batch --yes --no-default-keyring "
             "--keyring $GNUPGHOME/pubring.kbx --trust-model always "
             "--encrypt --recipient-file '%s' >> '%s/nginx-%s.log.gpg'",
             gnupghome, key_file, log_buf, key_file, log_path, date_buf);

    int ret = system(cmd_buf);
    if (ret != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "securelog: GPG encryption failed (code %d)", ret);
    }

    char rm_cmd[256];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf '%s'", gnupghome);
    system(rm_cmd);

    return NGX_OK;
}

static ngx_int_t ngx_http_gpg_securelog_init(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (!h) return NGX_ERROR;
    *h = ngx_http_gpg_securelog_handler;
    return NGX_OK;
}

static void *ngx_http_gpg_securelog_create_main_conf(ngx_conf_t *cf) {
    ngx_http_gpg_securelog_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gpg_securelog_conf_t));
    return conf;
}

static ngx_command_t ngx_http_gpg_securelog_commands[] = {
    {
        ngx_string("gpg_log_publickey_file"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_gpg_securelog_conf_t, gpg_publickey_file),
        NULL
    },
    {
        ngx_string("gpg_log_path"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_gpg_securelog_conf_t, log_path),
        NULL
    },
    {
        ngx_string("gpg_log_rotation"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_gpg_securelog_conf_t, rotation_mode),
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_gpg_securelog_module_ctx = {
    NULL,
    ngx_http_gpg_securelog_init,
    ngx_http_gpg_securelog_create_main_conf,
    NULL, NULL, NULL, NULL, NULL
};

ngx_module_t ngx_http_gpg_securelog = {
    NGX_MODULE_V1,
    &ngx_http_gpg_securelog_module_ctx,
    ngx_http_gpg_securelog_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};
