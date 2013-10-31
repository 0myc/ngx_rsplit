
/*
 * Copyright (C) Eugene Mychlo
 * 
 * Licence: This module could be distributed under the
 * same terms as Nginx itself.
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
    off_t        size;
} ngx_http_range_t;


typedef struct {
    ngx_flag_t          do_split;

    size_t              frag_size;
    ssize_t             resp_body_len;
    ssize_t             offset;
    ngx_uint_t          cur_frag;
    ngx_str_t           cur_range;
    ngx_str_t           req_range_str;
    ngx_http_range_t    req_range;

    unsigned            subrequest_wait:1;
    unsigned            subrequest_done:1;

    unsigned            send_range:1;
    unsigned            req_done:1;
    unsigned            send_not_satisfiable:1;  //RANGE_NOT_SATISFIABLE
} ngx_http_rsplit_ctx_t;


static void * ngx_http_rsplit_create_loc_conf(ngx_conf_t *);
static char * ngx_http_rsplit_merge_loc_conf(ngx_conf_t *, void *, void *);
static ngx_int_t ngx_http_rsplit_filter_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_rsplit_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_rsplit_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_rsplit_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_rsplit_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_rsplit_range_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_int_t ngx_http_rsplit_headers_send(ngx_http_request_t *r,
    ngx_http_rsplit_ctx_t *ctx);

static ngx_int_t ngx_http_rsplit_parse_req_range(ngx_http_rsplit_ctx_t *ctx);
static ngx_int_t ngx_http_rsplit_set_req_range(ngx_http_request_t *r,
    ngx_http_rsplit_ctx_t *ctx);

static ngx_table_elt_t * ngx_http_rsplit_get_resp_range(ngx_http_request_t *r);
static ngx_int_t ngx_http_rsplit_parse_resp_range(ngx_http_rsplit_ctx_t *ctx,
    ngx_table_elt_t *ht);

static ngx_int_t ngx_http_rsplit_singlepart_header(ngx_http_request_t *r,
    ngx_http_rsplit_ctx_t *ctx);
static ngx_int_t ngx_http_rsplit_singlepart_body(ngx_http_request_t *r,
    ngx_http_rsplit_ctx_t *ctx, ngx_chain_t *in);
static ngx_int_t ngx_http_rsplit_body_next_frag(ngx_http_request_t *r,
    ngx_http_rsplit_ctx_t *ctx);

static ngx_int_t ngx_http_rsplit_range_not_satisfiable(ngx_http_request_t *r,
    ngx_http_rsplit_ctx_t *ctx);
static ngx_int_t ngx_http_rsplit_resume_handler(ngx_http_request_t *r,
    void *data, ngx_int_t rc);

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
    ngx_http_rsplit_add_variables, /* preconfiguration */
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

static ngx_str_t  ngx_http_rsplit_range = ngx_string("rsplit_range");


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
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "http rsplit SUBREQUEST");
        return NGX_DECLINED;
    }


    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    rslcf = ngx_http_get_module_loc_conf(r, ngx_http_rsplit_module);
    if (rslcf == NULL || !rslcf->enable ) {
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

    ctx->do_split = 1;
    ctx->resp_body_len = 0;
    ctx->frag_size = rslcf->frag_size;
    ctx->req_range_str.len = 0;
    ctx->cur_frag = 0;

    if (r->headers_in.range) {
        if (clcf->max_ranges > 0) {
            ctx->req_range_str.data  = r->headers_in.range->value.data;
            ctx->req_range_str.len  = r->headers_in.range->value.len;
        }

    }

    if (ctx->req_range_str.len > 0) {
        rc = ngx_http_rsplit_parse_req_range(ctx);
        switch(rc) {
        case NGX_OK:
            ctx->cur_frag = ctx->req_range.start / rslcf->frag_size;
            ctx->send_range = 1;
            break;

        case NGX_ERROR:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;

        case NGX_HTTP_RANGE_NOT_SATISFIABLE:
            ctx->send_not_satisfiable = 1;

        case NGX_DECLINED:
            break;
        }
    }

    rc = ngx_http_rsplit_set_req_range(r, ctx);
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->cur_frag++;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "http rsplit request range %V", &ctx->cur_range);

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_rsplit_header_filter(ngx_http_request_t *r)
{
    ngx_http_rsplit_ctx_t       *ctx;
    ngx_int_t                   rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_rsplit_module);

    if (ctx == NULL || r != r->main) {
        return ngx_http_next_header_filter(r);
    }

    if (!ctx->do_split || r->headers_out.content_length_n == -1)
    {
        return ngx_http_next_header_filter(r);
    }


    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "http rsplit header filter");

    switch (r->headers_out.status) {
    case NGX_HTTP_PARTIAL_CONTENT:
        
        r->allow_ranges = 1;
        rc = ngx_http_rsplit_headers_send(r, ctx);

        switch (rc) {
        case NGX_ERROR:
            return NGX_ERROR;

        case NGX_HTTP_RANGE_NOT_SATISFIABLE:
            return ngx_http_rsplit_range_not_satisfiable(r, ctx);
        }

        break;

    default:
        ctx->do_split = 0;
        break;
    }

    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_rsplit_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_rsplit_ctx_t   *ctx;
    ngx_int_t               rc, last;
    ngx_chain_t             *cl;

    ctx = ngx_http_get_module_ctx(r == r->main ? r : r->main,
                                                    ngx_http_rsplit_module);

    if (ctx == NULL || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }
    
    if (!ctx->do_split) {
        return ngx_http_next_body_filter(r, in);
    }


    if (ctx->req_done) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rsplit req_done");
        ctx->do_split = 0;
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    last = 0;
    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            last = 1;

            if (r == r->main && !ctx->subrequest_wait) {
                cl->buf->last_buf = 0;
                cl->buf->sync = 1;
            }
        }
    }

    if (ctx->send_range) {
        rc = ngx_http_rsplit_singlepart_body(r, ctx, in);
    } else {
        rc = ngx_http_next_body_filter(r, in);
    }

    if (rc == NGX_ERROR) {
        return rc;
    }

    if (!ctx->subrequest_done) {
        if (ctx->subrequest_wait || !last) {
            return rc;
        }
    }

    return ngx_http_rsplit_body_next_frag(r, ctx);
}


static ngx_int_t
ngx_http_rsplit_singlepart_body(ngx_http_request_t *r,
     ngx_http_rsplit_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_http_range_t  *range;
    ngx_chain_t       *out, *cl, **ll;
    off_t              start, last;
    ngx_buf_t         *buf;


    if (!ctx) {
        return NGX_ERROR;
    }

    out = NULL;
    ll = &out;
    range = &ctx->req_range;

    for (cl = in; cl; cl = cl->next) {

        buf = cl->buf;

        start = ctx->offset;
        last = ctx->offset + ngx_buf_size(buf);

        ctx->offset = last;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "rsplit body buf: %O-%O", start, last);

        if (ngx_buf_special(buf)) {
            *ll = cl;
            ll = &cl->next;
            continue;
        }

/* 
 * 1. start < last <= range->start < range->end    - skip
 * 2. start <= range->start <= last <= range->end  - star proccesing
 * 3. start <= range->start < range->end <= last
 * 4. range->start < start < last <= range->end
 * 5. range->start < start <= range->end <= last  - stop proccesing
 * 6. range->start < range->end <= start < last    - skip
 * 
 */ 

        /* case 1,6 */
        if (range->start >= last || range->end <= start) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rsplit body buf, skip %O-%O", start, last);

            if (buf->in_file) {
                buf->file_pos = buf->file_last;
            }

            buf->pos = buf->last;
            buf->sync = 1;

            if (range->end < start) {
                ctx->do_split = 0;
            }

            continue;
        }

/*
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "rsplit start range body %O-%O", range->start, range->end);
*/

        /* case 2,3 */
        if (range->start > start) {

            if (buf->in_file) {
                buf->file_pos += range->start - start;
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rsplit buf->file_pos %O", buf->file_pos);
            }

            if (ngx_buf_in_memory(buf)) {
                buf->pos += (size_t) (range->start - start);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rsplit buf->pos %O", buf->pos);
            }
        }

        if (range->end <= last) {

            if (buf->in_file) {
                buf->file_last -= last - range->end;
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rsplit buf->file_last %O", buf->file_last);
            }

            if (ngx_buf_in_memory(buf)) {
                buf->last -= (size_t) (last - range->end);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rsplit buf->last %O", buf->last);
            }

            buf->last_buf = 1;
            *ll = cl;
            cl->next = NULL;

            break;
        }


        *ll = cl;
        ll = &cl->next;

    }

    if (out == NULL) {
        return NGX_OK;
    }

    return ngx_http_next_body_filter(r, out);
}



static ngx_int_t
ngx_http_rsplit_body_next_frag(ngx_http_request_t *r,
    ngx_http_rsplit_ctx_t *ctx)
{
    ngx_http_request_t          *sr;
    ngx_int_t                   rc;
    ngx_http_post_subrequest_t  *psr;

    rc = ngx_http_rsplit_set_req_range(r, ctx);
    if (rc != NGX_OK) {
        return rc;
    }

    if (ctx->req_done) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http rsplit subrequest range %V %O",
            &ctx->cur_range,
            ctx->resp_body_len);

    ctx->cur_frag++;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }

    psr->handler = ngx_http_rsplit_resume_handler;

    ctx->subrequest_wait = 1;
    ctx->subrequest_done = 0;

    return ngx_http_subrequest(r, &r->uri, NULL, &sr, psr, 0);
}


static ngx_int_t
ngx_http_rsplit_resume_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_rsplit_ctx_t          *ctx;

    if (rc == NGX_ERROR || r->connection->error) {
        return rc;
    }

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_rsplit_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->subrequest_wait = 0;
    ctx->subrequest_done = 1;

    return NGX_OK;
}



static ngx_int_t
ngx_http_rsplit_range_not_satisfiable(ngx_http_request_t *r,
     ngx_http_rsplit_ctx_t *ctx)
{
    ngx_table_elt_t    *content_range;

    content_range = ngx_http_rsplit_get_resp_range(r);

    /* Content-Range header is not found in r->headers_out */
    if (content_range == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_rsplit_parse_resp_range(ctx, content_range) == NGX_ERROR) {
        return NGX_ERROR;
    }


    r->headers_out.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;
    r->headers_out.status_line.len = 0;

    content_range->value.data = ngx_pnalloc(r->pool,
                                       sizeof("bytes */") - 1 + NGX_OFF_T_LEN);

    if (content_range->value.data == NULL) {
        return NGX_ERROR;
    }

    content_range->value.len = ngx_sprintf(content_range->value.data,
                                           "bytes */%O",
                                           ctx->resp_body_len)
                               - content_range->value.data;

    ngx_http_set_ctx(r, NULL, ngx_http_rsplit_module);
    ngx_http_clear_content_length(r);

    return NGX_HTTP_RANGE_NOT_SATISFIABLE;
}


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
    ssize_t     first, last;

    first = ctx->frag_size * ctx->cur_frag;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rsplit ctx->cur_frag %d", ctx->cur_frag);

    if (ctx->resp_body_len == 0) { // unknown response length
        last = ctx->frag_size * (ctx->cur_frag + 1) - 1;
    } else {
        if (ctx->resp_body_len - 1 < first) {
            ctx->req_done = 1;
            return NGX_OK;
        }

        last = ngx_min((ssize_t)(ctx->frag_size * (ctx->cur_frag + 1) - 1),
                                                    ctx->resp_body_len - 1);
    }

    if (!ctx->cur_range.data) {
        ctx->cur_range.data = ngx_pnalloc(r->pool, 2 * NGX_INT64_LEN + 7);
    }

    if (ctx->cur_range.data == NULL) {
        return NGX_ERROR;
    }

    ctx->cur_range.len = ngx_sprintf(ctx->cur_range.data,
            "bytes=%z-%z", first, last) - ctx->cur_range.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rsplit ngx_http_rsplit_set_req_range %V", &ctx->cur_range);

    return NGX_OK;
}

static ngx_table_elt_t *
ngx_http_rsplit_get_resp_range(ngx_http_request_t *r)
{
    ngx_table_elt_t     *h;
    ngx_list_part_t     *part;
    ngx_uint_t          i;

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
            return &h[i];
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_rsplit_parse_resp_range(ngx_http_rsplit_ctx_t *ctx,
    ngx_table_elt_t *ht)
{
    ngx_str_t   *cr;
    u_char      *p;
    ssize_t     len;
    ngx_uint_t  i;

    cr = &ht->value;
    if (cr == NULL || cr->len <= sizeof("bytes -/") - 1) {
        return NGX_ERROR;
    }

    /*Content-Range: bytes 8-100/1685044 */ 

    i = 6;  // skip 6 bytes i.e. "bytes "
    p = cr->data + 6;

    ctx->offset = NGX_ERROR;
    for ( ; i < cr->len; i++, p++) {
        if (*p == '-') {
            ctx->offset = ngx_atosz(cr->data + 6, i - 6);
            break;
        }
    }

    if (ctx->offset == NGX_ERROR)
        return NGX_ERROR;


    len = NGX_ERROR;
    for ( ; i < cr->len; i++, p++) {
        if ( *p == '/' ) {
            if (cr->len - i - 1 <= 0) {
                return NGX_ERROR;
            }

            len = ngx_atosz(p + 1, cr->len - i - 1);
            break;
        }
    }

    if (len == NGX_ERROR) {
        return NGX_ERROR;
    }

    ctx->resp_body_len = len;

    return NGX_OK;
}



static ngx_int_t
ngx_http_rsplit_headers_send(ngx_http_request_t *r, ngx_http_rsplit_ctx_t *ctx)
{
    ngx_table_elt_t    *ht;
    ngx_http_range_t   *rr;


    if (ctx->send_not_satisfiable) {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    ht = ngx_http_rsplit_get_resp_range(r);

    /* Content-Range header is not found in r->headers_out */
    if (ht == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_rsplit_parse_resp_range(ctx, ht) == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (ctx->send_range) {
        rr = &ctx->req_range;

        if (rr->end == NGX_MAX_OFF_T_VALUE) {
            if (rr->size == NGX_MAX_OFF_T_VALUE) {
                // Range: bytes=SSSS-

                if (ctx->resp_body_len < rr->start) {
                    return NGX_HTTP_RANGE_NOT_SATISFIABLE;
                }


                rr->end = ctx->resp_body_len;
                rr->size = ctx->resp_body_len - rr->start;
            } else {
                // Range: bytes=-EEEE

                if (ctx->resp_body_len < rr->size) {
                    goto without_range;
                }

                rr->start = ctx->resp_body_len - rr->size;
                rr->end = ctx->resp_body_len;
            }
        } else {
            // Range: bytes=SSSS-EEEE

            if (ctx->resp_body_len < rr->end) {
                rr->end = ctx->resp_body_len;
                rr->size = ctx->resp_body_len - rr->start;
            }
        }

        r->headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
        r->headers_out.status_line.len = 0;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "rsplit send status NGX_HTTP_PARTIAL_CONTENT");

        r->headers_out.content_range = ht;
        return ngx_http_rsplit_singlepart_header(r, ctx);
    }


without_range:
    ctx->send_range = 0;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.status_line.len = 0;
    r->headers_out.content_length_n = ctx->resp_body_len;

#if 0
    if (r->headers_in.range) {
        r->headers_in.range->value.len = 0;
    }
#endif

    // XXX: dirty-hack
    ht->hash = 0;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    return  NGX_OK;
}

static ngx_int_t
ngx_http_rsplit_parse_req_range(ngx_http_rsplit_ctx_t *ctx) 
{
    u_char            *p;
    off_t              start, end, size;
    ngx_uint_t         suffix;

    if (ctx->req_range_str.len == 0 ||  ctx->req_range_str.data == NULL) {
        return NGX_DECLINED;
    }

    p = ctx->req_range_str.data + 6;

    size = 0;
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

        /* multipart range request is not supported */
        if (*p == ',') {
            return NGX_DECLINED;
        }

        if (*p == '\0') {
            end = NGX_MAX_OFF_T_VALUE;
            goto found;
        }

    } else {
        suffix = 1;
        p++;
    }

    while (*p == ' ') { p++; }

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

    /* multipart range request is not supported */
    if (*p == ',') {
        return NGX_DECLINED;
    }

found:

    if (end == NGX_MAX_OFF_T_VALUE) {
        size = NGX_MAX_OFF_T_VALUE;
    } else if (suffix) {
        size = end;
        start = 0;
        end = NGX_MAX_OFF_T_VALUE;
    } else {
        if (start > end) {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        end++;

        size = end - start;
    }


    ctx->req_range.start = start;
    ctx->req_range.end = end;
    ctx->req_range.size = size;

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

    range = &ctx->req_range;

    value->len = ngx_sprintf(value->data, "bytes %O-%O/%O",
                            range->start, range->end - 1, ctx->resp_body_len)
                            - value->data;

    r->headers_out.content_length_n = range->end - range->start;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_rsplit_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_rsplit_range,
        NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH);

    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_rsplit_range_variable;

    return NGX_OK;
}


static ngx_int_t
ngx_http_rsplit_range_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_rsplit_ctx_t  *ctx;

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;


    ctx = ngx_http_get_module_ctx(r == r->main ? r : r->main,
                                                ngx_http_rsplit_module);

    if (ctx == NULL || ctx->frag_size == 0) {
        v->not_found = 1;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "var rsplit NOT FOUND %p", ctx);
        return NGX_OK;
    }

    v->data = ctx->cur_range.data;
    v->len = ctx->cur_range.len;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "var rsplit_range %v", v);

    return NGX_OK;
}
