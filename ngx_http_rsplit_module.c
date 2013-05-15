
/*
 * Copyright (C) Igor Sysoev
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    size_t          frag_size;
    ngx_flag_t      enable;
} ngx_http_rsplit_loc_conf_t;

typedef struct {
    off_t        start;
    off_t        end;
    ngx_str_t    content_range;
} ngx_http_range_t;


typedef struct {
    ngx_flag_t      start;

    size_t          frag_size;
    ssize_t         resp_body_len;
    ngx_uint_t      cur_frag;
    ngx_str_t       req_range_str;
    ngx_array_t     req_ranges;
} ngx_http_rsplit_ctx_t;


static void * ngx_http_rsplit_create_loc_conf(ngx_conf_t *);
static char * ngx_http_rsplit_merge_loc_conf(ngx_conf_t *, void *, void *);
static ngx_int_t ngx_http_rsplit_filter_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_rsplit_headers_send(ngx_http_request_t *r,
    ngx_http_rsplit_ctx_t *ctx);
static ngx_int_t ngx_http_rsplit_set_req_range(ngx_http_request_t *r,
    ngx_http_rsplit_ctx_t *ctx);

static ngx_int_t ngx_http_rsplit_range_parse(ngx_http_rsplit_ctx_t *ctx,
    ngx_uint_t ranges);

static ngx_int_t ngx_http_rsplit_singlepart_header(ngx_http_request_t *r,
    ngx_http_rsplit_ctx_t *ctx);
static ngx_int_t ngx_http_rsplit_multipart_header(ngx_http_request_t *r,
    ngx_http_rsplit_ctx_t *ctx);


static ngx_int_t ngx_http_rsplit_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_rsplit_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_rsplit_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);

static ngx_command_t  ngx_http_rsplit_commands[] = {

    { ngx_string("rsplit"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_rsplit_loc_conf_t, enable),
      NULL },

    { ngx_string("rsplit_frag_size"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_rsplit_loc_conf_t, frag_size),
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_rsplit_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_rsplit_filter_init,   /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_rsplit_create_loc_conf,  /* create location configuration */
    ngx_http_rsplit_merge_loc_conf,   /* merge location configuration */
};


ngx_module_t  ngx_http_rsplit_module = {
    NGX_MODULE_V1,
    &ngx_http_rsplit_module_ctx,      /* module context */
    ngx_http_rsplit_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_rsplit_handler(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    //ngx_log_t                 *log;
    //ngx_http_request_t        *sr;
    //ngx_http_range_split_loc_conf_t *srlcf;
    ngx_http_rsplit_loc_conf_t  *rslcf;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_rsplit_ctx_t       *ctx;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    if (r != r->main) {
        return NGX_DECLINED;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    rslcf = ngx_http_get_module_loc_conf(r, ngx_http_rsplit_module);
    if ( rslcf == NULL || !rslcf->enable ) {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_rsplit_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_rsplit_module);

    ctx->cur_frag = 0;
    ctx->start = 1;
    ctx->resp_body_len = 0;
    ctx->frag_size = rslcf->frag_size;


    if (r->headers_in.range) {
        if (clcf->max_ranges > 0) {
            ctx->req_range_str.data  = r->headers_in.range->value.data;
            ctx->req_range_str.len  = r->headers_in.range->value.len;
        }

    } else {
        r->headers_in.range = ngx_list_push(&r->headers_in.headers);
        if (r->headers_in.range == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_str_set(&r->headers_in.range->key, "Range");
    }

    rc = ngx_http_rsplit_set_req_range(r, ctx);

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->cur_frag++;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "http rsplit request range %V", &r->headers_in.range->value);

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_rsplit_header_filter(ngx_http_request_t *r)
{
    ngx_http_rsplit_ctx_t       *ctx;
    ngx_int_t                   rc;

    if (r->header_only
        || r != r->main
        || r->headers_out.content_length_n == -1)
    {
        return ngx_http_next_header_filter(r);
    }


    ctx = ngx_http_get_module_ctx(r, ngx_http_rsplit_module);

    if (ctx == NULL || !ctx->start) {
        return ngx_http_next_header_filter(r);
    }

/*
    r->headers_in.range->value.data = ctx->req_range.data;
    r->headers_in.range->value.len = ctx->req_range.len;
*/

    switch (r->headers_out.status) {
    case NGX_HTTP_PARTIAL_CONTENT:
        rc = ngx_http_rsplit_headers_send(r, ctx);

        if (rc == NGX_ERROR) {
            ctx->start = 0;
            return NGX_ERROR;
        }


        break;

    default:
        ctx->start = 0;
        break;
    }
        
    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_rsplit_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_rsplit_ctx_t     *ctx;
    ngx_http_request_t        *sr;
    ngx_int_t                 rc;


    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_rsplit_module);

    if (r != r->main || ctx == NULL || !ctx->start) {
        return ngx_http_next_body_filter(r, in);
    }

    if (in->buf->last_buf || in->buf->last_in_chain) {
        rc = ngx_http_rsplit_set_req_range(r, ctx);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "rsplit body filter Content-Length: %O", ctx->resp_body_len);

        if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "http rsplit subrequest range %V %O",
                 &r->headers_in.range->value,
                 ctx->resp_body_len);

        ctx->cur_frag++;

        rc = ngx_http_subrequest(r, &r->uri, NULL, &sr, NULL, 0);

        switch(rc) {
        case NGX_OK:
            return ngx_http_next_body_filter(r, in);
            break;

        case NGX_DONE:
        case NGX_AGAIN:
        case NGX_ERROR:
            return rc;
            break;
        }
    }

    return ngx_http_next_body_filter(r, in);
}



//static ngx_int_t
//ngx_http_rsplit_range_not_satisfiable(ngx_http_request_t *r,
//     ngx_http_rsplit_ctx_t *ctx)
//{
//    ngx_table_elt_t  *content_range;
//
//    r->headers_out.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;
//    content_range = r->headers_out.content_range;
//
//    content_range->value.data = ngx_pnalloc(r->pool,
//                                       sizeof("bytes */") - 1 + NGX_OFF_T_LEN);
//    if (content_range->value.data == NULL) {
//        return NGX_ERROR;
//    }
//
//    content_range->value.len = ngx_sprintf(content_range->value.data,
//                                           "bytes */%O",
//                                           ctx->resp_body_len)
//                               - content_range->value.data;
//
//    ngx_http_clear_content_length(r);
//
//    return NGX_HTTP_RANGE_NOT_SATISFIABLE;
//}


static void *
ngx_http_rsplit_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_rsplit_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rsplit_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->frag_size = NGX_CONF_UNSET_SIZE;

    return conf;
}



static char *
ngx_http_rsplit_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_rsplit_loc_conf_t *prev = parent;
    ngx_http_rsplit_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_size_value(conf->frag_size, prev->frag_size, 1024*1024);

    return NGX_CONF_OK;
}



static ngx_int_t
ngx_http_rsplit_filter_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_handler_pt        *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* install the tracking handler */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_rsplit_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_rsplit_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_rsplit_body_filter;

    return NGX_OK;
}

static ngx_int_t
ngx_http_rsplit_set_req_range(ngx_http_request_t *r, ngx_http_rsplit_ctx_t *ctx)
{
    ngx_str_t       *val;
    ssize_t     first, last;

    first = ctx->frag_size * ctx->cur_frag;

    if (ctx->resp_body_len == 0) { // unknown response length
        last = ctx->frag_size * (ctx->cur_frag + 1) - 1;
    } else {
        last = ngx_min((ssize_t)(ctx->frag_size * (ctx->cur_frag + 1) - 1),
                                                    ctx->resp_body_len - 1);
    }

    val = &r->headers_in.range->value;
    val->data = ngx_pnalloc(r->pool, 2 * NGX_INT64_LEN + 7);
    if (val->data == NULL) {
        return NGX_ERROR;
    }

    val->len = ngx_sprintf(val->data, "bytes=%z-%z", first, last) - val->data;
    return NGX_OK;
}



static ngx_int_t
ngx_http_rsplit_headers_send(ngx_http_request_t *r, ngx_http_rsplit_ctx_t *ctx)
{
    ngx_http_core_loc_conf_t *clcf;
    u_char            *p;
    ngx_uint_t         i;
    ssize_t            len;
    ngx_table_elt_t    *h, *ht;
    ngx_list_part_t    *part;
    ngx_str_t          *cr;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if ( h[i].key.len == sizeof("Content-Range") - 1 && 
            ngx_strcasecmp((u_char *)"Content-Range", h[i].key.data) == 0)
        {
            ht = &h[i];
            cr = &h[i].value;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rsplit header Content-Range: %V", &h[i].value );
        }
    }

    
    if (cr == NULL || cr->len <= sizeof("bytes -/") - 1) {
        return NGX_ERROR;
    }


    i = 0;
    p = cr->data;

    for ( ; i < cr->len; i++, p++) {
        if ( *p == '/' )
            break;
    }

    if (cr->len - i - 1 <= 0) {
        return NGX_ERROR;
    }

    len = ngx_atosz(p + 1, cr->len - i - 1);
    if (len == NGX_ERROR)
        return NGX_ERROR;

    ctx->resp_body_len = len;

    if (ngx_array_init(&ctx->req_ranges, r->pool, 1, sizeof(ngx_http_range_t))
            != NGX_OK)
    {
        return NGX_ERROR;
    }

    switch (ngx_http_rsplit_range_parse(ctx, clcf->max_ranges)) {

    case NGX_OK:
        r->headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
        r->headers_out.status_line.len = 0;
        r->allow_ranges = 1;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "rsplit NGX_HTTP_PARTIAL_CONTENT %i", ctx->req_ranges.nelts);

        if (ctx->req_ranges.nelts == 1) {
            r->headers_out.content_range = ht;
            return ngx_http_rsplit_singlepart_header(r, ctx);
        }

        return ngx_http_rsplit_multipart_header(r, ctx);
    
    case NGX_ERROR:
        return NGX_ERROR;

    default: /* NGX_DECLINED */
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.status_line.len = 0;
        r->headers_out.content_length_n = ctx->resp_body_len;
        r->allow_ranges = 0;

        // XXX: dirty-hack
        ht->hash = 0;
        break;
    }

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    return  NGX_OK;
}


static ngx_int_t
ngx_http_rsplit_range_parse(ngx_http_rsplit_ctx_t *ctx, ngx_uint_t ranges)
{
    u_char            *p;
    off_t              start, end, size, content_length;
    ngx_uint_t         suffix;
    ngx_http_range_t  *range;

    if (ctx->req_range_str.data == NULL)
        return NGX_DECLINED;

    p = ctx->req_range_str.data + 6;
    size = 0;
    content_length = ctx->resp_body_len;

    for ( ;; ) {
        start = 0;
        end = 0;
        suffix = 0;

        while (*p == ' ') { p++; }

        if (*p != '-') {
            if (*p < '0' || *p > '9') {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            while (*p >= '0' && *p <= '9') {
                start = start * 10 + *p++ - '0';
            }

            while (*p == ' ') { p++; }

            if (*p++ != '-') {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            while (*p == ' ') { p++; }

            if (*p == ',' || *p == '\0') {
                end = content_length;
                goto found;
            }

        } else {
            suffix = 1;
            p++;
        }

        if (*p < '0' || *p > '9') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        while (*p >= '0' && *p <= '9') {
            end = end * 10 + *p++ - '0';
        }

        while (*p == ' ') { p++; }

        if (*p != ',' && *p != '\0') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        if (suffix) {
            start = content_length - end;
            end = content_length - 1;
        }

        if (end >= content_length) {
            end = content_length;

        } else {
            end++;
        }

    found:

        if (start < end) {
            range = ngx_array_push(&ctx->req_ranges);
            if (range == NULL) {
                return NGX_ERROR;
            }

            range->start = start;
            range->end = end;

            size += end - start;

            if (ranges-- == 0) {
                return NGX_DECLINED;
            }
        }

        if (*p++ != ',') {
            break;
        }
    }

    if (ctx->req_ranges.nelts == 0) {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    if (size > content_length) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_rsplit_singlepart_header(ngx_http_request_t *r,
    ngx_http_rsplit_ctx_t *ctx)
{
    ngx_http_range_t  *range;
    ngx_str_t * value = &r->headers_out.content_range->value;

    value->data = ngx_pnalloc(r->pool,
                                sizeof("bytes -/") - 1 + 3 * NGX_OFF_T_LEN);

    if (value->data == NULL) {
        return NGX_ERROR;
    }

    /* "Content-Range: bytes SSSS-EEEE/TTTT" header */

    range = ctx->req_ranges.elts;

    value->len = ngx_sprintf(value->data, "bytes %O-%O/%O",
                            range->start, range->end - 1, ctx->resp_body_len)
                            - value->data;

    r->headers_out.content_length_n = range->end - range->start;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    return ngx_http_next_header_filter(r);
}



static ngx_int_t
ngx_http_rsplit_multipart_header(ngx_http_request_t *r,
    ngx_http_rsplit_ctx_t *ctx)
{
    return NGX_OK;

}
