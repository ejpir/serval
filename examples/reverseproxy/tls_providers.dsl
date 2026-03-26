# reverseproxy TLS provider examples
# NOTE: runtime currently binds/serves the first listener for one process instance.

config.component.pool=simple
config.component.metrics=prometheus
config.component.tracing=noop
# For OTEL instead:
# config.component.tracing=otel
# config.component.tracing.otel.endpoint=http://127.0.0.1:4318/v1/traces

# Static certificate/key provider
listener l-static 0.0.0.0:8443 tls.provider=static tls.static.cert_path=/etc/serval/tls/fullchain.pem tls.static.key_path=/etc/serval/tls/privkey.pem

# Self-signed provider (boot-time generation/reuse)
listener l-selfsigned 0.0.0.0:9443 tls.provider=selfsigned tls.selfsigned.state_dir=/var/lib/serval/reverseproxy tls.selfsigned.domain=dev.internal.example tls.selfsigned.rotate_on_boot=false

# ACME provider (self-signed bootstrap -> ACME issue -> hot activation)
listener l-acme 0.0.0.0:443 tls.provider=acme tls.acme.directory_url=https://acme-v02.api.letsencrypt.org/directory tls.acme.contact_email=ops@example.com tls.acme.state_dir=/var/lib/serval/reverseproxy-acme tls.acme.domain=api.example.com

pool p1 upstream=http://127.0.0.1:18001
plugin authz fail_policy=fail_closed
chain c1 plugin=authz

route r-static listener=l-static host=example-static.com path=/ pool=p1 chain=c1
route r-selfsigned listener=l-selfsigned host=example-selfsigned.com path=/ pool=p1 chain=c1
route r-acme listener=l-acme host=example-acme.com path=/ pool=p1 chain=c1
