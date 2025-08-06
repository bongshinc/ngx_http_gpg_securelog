#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/stat.h>
#include <time.h>

#define DEFAULT_GPG_KEY_DIR "conf/gpg_keys"
#define DEFAULT_GPG_LOG_SUBDIR "securelog"

typedef enum {
    ROTATE_HOURLY,
    ROTATE_DAILY,
    ROTATE_WEEKLY,
    ROTATE_MONTHLY
} rotate_mode_t;

typedef struct {
    ngx_str_t publickey_file;   // 공개키 파일 경로
    ngx_str_t log_path;         // 로그 저장 디렉토리
    ngx_str_t rotation_mode;    // 로그 회전 주기
} ngx_http_gpg_securelog_conf_t;

// 기본 로그 경로를 동적으로 얻기 위한 함수 선언
static ngx_str_t get_default_log_path(ngx_conf_t *cf);

static ngx_int_t ngx_http_gpg_securelog_handler(ngx_http_request_t *r) {
    ngx_http_gpg_securelog_conf_t *conf;
    conf = ngx_http_get_module_main_conf(r, ngx_http_gpg_securelog);

    // 요청 기본 정보 추출
    ngx_str_t remote_addr = r->connection->addr_text;
    ngx_str_t method = r->method_name;
    ngx_str_t uri = r->uri;

    ngx_str_t user_agent;
    if (r->headers_in.user_agent) {
        user_agent = r->headers_in.user_agent->value;
    } else {
        user_agent = ngx_string("-");
    }

    time_t rawtime;
    struct tm *timeinfo;
    char date_buf[32];
    char log_buf[1024];
    char cmd_buf[4096];

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    // 로그 회전 모드 결정 (기본 DAILY)
    rotate_mode_t mode = ROTATE_DAILY;
    if (conf->rotation_mode.len > 0) {
        if (ngx_strncmp(conf->rotation_mode.data, (u_char *)"hourly", 6) == 0) {
            mode = ROTATE_HOURLY;
        } else if (ngx_strncmp(conf->rotation_mode.data, (u_char *)"weekly", 6) == 0) {
            mode = ROTATE_WEEKLY;
        } else if (ngx_strncmp(conf->rotation_mode.data, (u_char *)"monthly", 7) == 0) {
            mode = ROTATE_MONTHLY;
        }
    }

    switch (mode) {
        case ROTATE_HOURLY:
            strftime(date_buf, sizeof(date_buf), "%Y%m%d-%H00", timeinfo);
            break;
        case ROTATE_DAILY:
            strftime(date_buf, sizeof(date_buf), "%Y%m%d-0000", timeinfo);
            break;
        case ROTATE_WEEKLY: {
            int week = timeinfo->tm_yday / 7 + 1;
            snprintf(date_buf, sizeof(date_buf), "%04dW%02d-0000", timeinfo->tm_year + 1900, week);
            break;
        }
        case ROTATE_MONTHLY:
            strftime(date_buf, sizeof(date_buf), "%Y%m-0000", timeinfo);
            break;
    }

    snprintf(log_buf, sizeof(log_buf),
             "%s [%s] \"%.*s %.*s\" \"%.*s\"\n",
             (char *)remote_addr.data,
             date_buf,
             (int)method.len, (char *)method.data,
             (int)uri.len, (char *)uri.data,
             (int)user_agent.len, (char *)user_agent.data);

    // 로그 저장 경로 (conf 설정 없으면 기본값)
    char *log_path = NULL;
    if (conf->log_path.len > 0) {
        log_path = (char *)ngx_pstrdup(r->pool, &conf->log_path);
    } else {
        // 기본값: ${NGINX_LOGS_PATH}/securelog
        ngx_str_t default_path = get_default_log_path(r->connection->log->file->log_level == 0 ? r->pool : r->pool);  // 그냥 pool 넘김
        log_path = (char *)ngx_pstrdup(r->pool, &default_path);
    }

    // 공개키 파일 (필수)
    if (conf->publickey_file.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "gpg_log_publickey_file is not configured");
        return NGX_ERROR;
    }

    char *pubkey_file = (char *)ngx_pstrdup(r->pool, &conf->publickey_file);

    // 디렉토리 존재 확인 및 없으면 생성 (간단히)
    struct stat st;
    if (stat(log_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        mkdir(log_path, 0700);
    }

    // GPG 암호화 명령어 작성
    snprintf(cmd_buf, sizeof(cmd_buf),
             "echo \"%s\" | gpg --encrypt --recipient-file %s --output %s/nginx-%s.log.gpg --batch --yes --trust-model always --armor --encrypt",
             log_buf, pubkey_file, log_path, date_buf);

    int ret = system(cmd_buf);
    (void)ret;

    return NGX_OK;
}

static ngx_int_t ngx_http_gpg_securelog_init(ngx_conf_t *cf) {
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_gpg_securelog_handler;

    return NGX_OK;
}

// NGINX 로그 경로 하위 securelog 디렉토리 기본값 반환
static ngx_str_t get_default_log_path(ngx_conf_t *cf) {
    ngx_str_t logs_path = ngx_string("/usr/local/nginx/logs");
    ngx_str_t securelog_subdir = ngx_string("/" DEFAULT_GPG_LOG_SUBDIR);

    // cf->cycle->log? 등 더 정확한 경로를 얻는 방법도 있음
    // 여기선 하드코딩 또는 사용자 설정으로 수정 가능

    // 임시로 동적 할당 없이 정적 배열로 처리
    static u_char path_buf[256];
    ngx_memcpy(path_buf, logs_path.data, logs_path.len);
    ngx_memcpy(path_buf + logs_path.len, securelog_subdir.data, securelog_subdir.len);
    path_buf[logs_path.len + securelog_subdir.len] = '\0';

    ngx_str_t full_path = {logs_path.len + securelog_subdir.len, path_buf};

    return full_path;
}

static void *ngx_http_gpg_securelog_create_main_conf(ngx_conf_t *cf) {
    ngx_http_gpg_securelog_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gpg_securelog_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->publickey_file.len = 0;
    conf->publickey_file.data = NULL;

    conf->log_path.len = 0;
    conf->log_path.data = NULL;

    conf->rotation_mode.len = 0;
    conf->rotation_mode.data = NULL;

    return conf;
}

static char *ngx_http_gpg_securelog_set_publickey(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_gpg_securelog_conf_t *gconf = conf;
    ngx_str_t *value = cf->args->elts;

    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty gpg_log_publickey_file");
        return NGX_CONF_ERROR;
    }

    gconf->publickey_file = value[1];

    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_gpg_securelog_commands[] = {
    {
        ngx_string("gpg_log_publickey_file"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_http_gpg_securelog_set_publickey,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_gpg_securelog_conf_t, publickey_file),
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
    NULL,                                  /* preconfiguration */
    ngx_http_gpg_securelog_init,           /* postconfiguration */

    ngx_http_gpg_securelog_create_main_conf,  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t ngx_http_gpg_securelog = {
    NGX_MODULE_V1,
    &ngx_http_gpg_securelog_module_ctx,
    ngx_http_gpg_securelog_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};
