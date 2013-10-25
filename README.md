ngx_rsplit
==========

# ngx_rsplit module

### Build

cd to NGINX source directory & run this:

    ./configure --add-module=<path-to-nginx-rsplit-module>
    make
    make install

### Example nginx.conf


    http {
        default_type  application/octet-stream;

        proxy_cache_path /tmp/cache keys_zone=mycache:10m inactive=5d max_size=300g;

        server {
            listen       80;
            server_name  _;

            location / {
                rsplit on;
                rsplit_frag_size 1024k;
                proxy_set_header Range $rsplit_range;

                proxy_pass http://origin;
                proxy_cache_key $uri$rsplit_range;
                proxy_cache mycache;
                proxy_cache_valid 200 206    5d;
            }

        }
    }
