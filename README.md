# scoop

## Examples
Use the DNS servers configured in `/etc/resolv.conf` to lookup the `AAAA` record of `example.com`. 
```
scoop AAAA example.com
```

Use Cloudflares hidden service to resolve `A` record of `example.com`. TLS verification is additionally performed on using the server name `1.1.1.1`.
```
scoop --proxy socks5h://127.0.0.1:9050 @tls://dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion#1.1.1.1 example.com
```
