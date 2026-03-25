listener l1 0.0.0.0:8080
pool pool-a upstream=http://127.0.0.1:8001
plugin plugin-a fail_policy=fail_closed
chain chain-a plugin=plugin-a
route route-a listener=l1 host=127.0.0.1 path=/ pool=pool-a chain=chain-a
