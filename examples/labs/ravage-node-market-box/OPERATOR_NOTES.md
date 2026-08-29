# Borough Market Operations Operator Notes

This file is for local assisted-mode benchmark runs only. Do not place these
details on the live target page.

## Warning

This lab intentionally contains serious vulnerabilities. It must only be run on
localhost or in an isolated training network. Do not deploy it to any public or
shared network.

## Seed Account

Use this account only when running the assisted lab profile:

```text
username: buyer
password: buyer123
```

## Flags

The default flags are:

- `flag{market_order_bola}`
- `flag{market_inventory_union_sqli}`
- `flag{market_jwt_admin_confusion}`
- `flag{market_proto_config_abuse}`
- `flag{market_internal_admin_pivot}`

## Useful Local Context

- Public URL: `http://127.0.0.1:8092`
- Internal service host allowed only through the vulnerable app: `market-internal`
- Internal metadata URL: `http://market-internal:9200/metadata`
- JWT cookie name: `market_session`
- JWT signing hint exposed by the frontend: `market-dev-secret`
