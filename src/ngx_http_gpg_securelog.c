/**
 * ngx_http_gpg_securelog.c
 * -------------------------
 * Author: 최봉신 (Bongshin, Choi)
 * Version: 1.0.0
 * Date: 2025-08-06
 *
 * Summary:
 * This NGINX module securely logs request information by encrypting it using GPGME with a public key.
 * Encrypted logs are saved to a specified directory as armored GPG files.
 *
 * Usage:
 *   nginx.conf
 *     gpg_log_publickey_file /path/to/public.key;
 *     gpg_log_dir /var/log/securelog;
 *
 * Build:
 *   ./configure --add-module=/path/to/ngx_http_gpg_securelog
 *   make && make install
 */
//
// Version: 1.0.1
// Description: NGINX module that encrypts request logs using GPGME and stores them securely.

// ngx_http_gpg_securelog.c

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <locale.h>
#include <gpgme.h>

#define DEFAULT_LOG_SUBDIR "securelog"

typedef struct {
    ngx_str_t publickey_file;  // Path to public key
    ngx_str_t log_dir;         // Directory to store encrypted logs
} ngx_http_gpg_securelog_conf_t;

static gpgme_ctx_t gpg_ctx = NULL;
static gpgme_key_t gpg_key = NULL;

// Initialize GPGME and import public key
static ngx_int_t ngx_http_gpg_securelog_init_gpg(ngx_conf_t *cf, ngx_http_gpg_securelog_conf_t *conf) {
    gpgme_error_t err;
    setlocale(LC_ALL, "");
    gpgme_check_version(NULL);

    err = gpgme_new(&gpg_ctx);
    if (err) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "gpgme_new() failed");
        return NGX_ERROR;
    }

    FILE *f = fopen((char *)conf->publickey_file.data, "r");
    if (!f) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Failed to open public key file: %s", conf->publickey_file.data);
        return NGX_ERROR;
    }

    gpgme_data_t keydata;
    err = gpgme_data_new_from_stream(&keydata, f);
    fclose(f);
    if (err) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "gpgme_data_new_from_stream() failed");
        return NGX_ERROR;
    }

    err = gpgme_op_import(gpg_ctx, keydata);
    gpgme_data_release(keydata);
    if (err) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "gpgme_op_import() failed");
        return NGX_ERROR;
    }

    err = gpgme_op_keylist_start(gpg_ctx, NULL, 0);
    if (err) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "gpgme_op_keylist_start() failed");
        return NGX_ERROR;
    }

    err = gpgme_op_keylist_next(gpg_ctx, &gpg_key);
    gpgme_op_keylist_end(gpg_ctx);
    if (err) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "gpgme_op_keylist_next() failed");
        return NGX_ERROR;
    }

    gpgme_set_armor(gpg_ctx, 1);
    return NGX_OK;
}

// Encrypt log message in memory
static ngx_int_t gpg_encrypt_log(ngx_pool_t *pool, const u_char *plaintext, size_t len, ngx_str_t *out) {
    gpgme_data_t plain, cipher;
    gpgme_error_t err;

    err = gpgme_data_new_from_mem(&plain, (const char *)plaintext, len, 0);
    if (err) return NGX_ERROR;

    err = gpgme_data_new(&cipher);
    if (err) {
        gpgme_data_release(plain);
        return NGX_ERROR;
    }

    gpgme_key_t keys[] = { gpg_key, NULL };
    err = gpgme_op_encrypt(gpg_ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, plain, cipher);
    gpgme_data_release(plain);
    if (err) {
        gpgme_data_release(cipher);
        return NGX_ERROR;
    }

    off_t size = gpgme_data_seek(cipher, 0, SEEK_END);
    gpgme_data_seek(cipher, 0, SEEK_SET);

    u_char *buf = ngx_palloc(pool, size);
    if (!buf) {
        gpgme_data_release(cipher);
        return NGX_ERROR;
    }

    ssize_t read_len = gpgme_data_read(cipher, buf, size);
    gpgme_data_release(cipher);
    if (read_len < 0) return NGX_ERROR;

    out->data = buf;
    out->len = (size_t)read_len;
    return NGX_OK;
}

// Log handler called during NGX_HTTP_LOG_PHASE
static ngx_int_t ngx_http_gpg_securelog_handler(ngx_http_request_t *r) {
    ngx_http_gpg_securelog_conf_t *conf;
    conf = ngx_http_get_module_main_conf(r, ngx_http_gpg_securelog);

    if (conf->publickey_file.len == 0) {
        return NGX_DECLINED;
    }

    u_char logmsg[1024];
    ngx_str_t null_str = ngx_null_string;
    ngx_snprintf(logmsg, sizeof(logmsg), "%V \"%V %V\" \"%V\"\n",
        &r->connection->addr_text,
        &r->method_name,
        &r->uri,
        r->headers_in.user_agent ? &r->headers_in.user_agent->value : &null_str);

    ngx_str_t encrypted_log;
    if (gpg_encrypt_log(r->pool, logmsg, ngx_strlen(logmsg), &encrypted_log) != NGX_OK) {
        return NGX_ERROR;
    }

    u_char log_file_path[NGX_MAX_PATH];
    ngx_snprintf(log_file_path, NGX_MAX_PATH, "%V/nginx.log.gpg", &conf->log_dir);

    FILE *fp = fopen((char *)log_file_path, "a");
    if (!fp) {
        return NGX_ERROR;
    }

    fwrite(encrypted_log.data, 1, encrypted_log.len, fp);
    fclose(fp);
    return NGX_OK;
}

// Register log handler in postconfiguration
static ngx_int_t ngx_http_gpg_securelog_postconfig(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;

    *h = ngx_http_gpg_securelog_handler;
    return NGX_OK;
}

// Create configuration
static void * ngx_http_gpg_securelog_create_conf(ngx_conf_t *cf) {
    ngx_http_gpg_securelog_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gpg_securelog_conf_t));
    if (conf == NULL) return NULL;

    ngx_str_t default_log_dir = ngx_string(DEFAULT_LOG_SUBDIR);
    conf->log_dir.len = default_log_dir.len;
    conf->log_dir.data = ngx_pstrdup(cf->pool, &default_log_dir);
    return conf;
}

// Initialize configuration
static char * ngx_http_gpg_securelog_init_conf(ngx_conf_t *cf, void *conf) {
    ngx_http_gpg_securelog_conf_t *gconf = conf;

    if (gconf->publickey_file.len == 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "gpg_log_publickey_file is not set");
    }

    if (gpg_ctx == NULL && gconf->publickey_file.len > 0) {
        if (ngx_http_gpg_securelog_init_gpg(cf, gconf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

// Configuration directives
static ngx_command_t ngx_http_gpg_securelog_commands[] = {
    {
        ngx_string("gpg_log_publickey_file"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_gpg_securelog_conf_t, publickey_file),
        NULL
    },
    {
        ngx_string("gpg_log_dir"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_gpg_securelog_conf_t, log_dir),
        NULL
    },
    ngx_null_command
};

// Module context
static ngx_http_module_t ngx_http_gpg_securelog_module_ctx = {
    NULL,                                  // preconfiguration
    ngx_http_gpg_securelog_postconfig,     // postconfiguration
    ngx_http_gpg_securelog_create_conf,    // create main configuration
    ngx_http_gpg_securelog_init_conf,      // init main configuration
    NULL, NULL, NULL, NULL
};

// Module definition
ngx_module_t ngx_http_gpg_securelog = {
    NGX_MODULE_V1,
    &ngx_http_gpg_securelog_module_ctx,    // module context
    ngx_http_gpg_securelog_commands,       // module directives
    NGX_HTTP_MODULE,                       // module type
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

