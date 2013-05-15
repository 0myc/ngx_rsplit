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

        server {
            listen       80;
            server_name  _;

            location / {
                rsplit on;
                rsplit_frag_size 1024k;
                proxy_pass http://origin;
            }

        }
    }
