config.component.pool=simple
config.component.metrics=noop
config.component.tracing=otel
config.component.tracing.otel.endpoint=http://127.0.0.1:4318/v1/traces
config.component.tracing.otel.service_name=serval-reverseproxy-basic
config.component.tracing.otel.service_version=1.0.0
config.component.tracing.otel.scope_name=serval.reverseproxy.basic
config.component.tracing.otel.scope_version=1.0.0

listener l1 0.0.0.0:8080
pool pool-a upstream=http://127.0.0.1:8001
plugin plugin-a fail_policy=fail_closed
chain chain-a plugin=plugin-a
route route-a listener=l1 host=127.0.0.1 path=/ pool=pool-a chain=chain-a
