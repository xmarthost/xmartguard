# XMart Host MCP for WHMCS

A WHMCS addon module that turns WHMCS into an **MCP (Model Context Protocol) server**, so Claude, ChatGPT, Claude Code, Cursor, VS Code, n8n and other AI assistants can read and manage WHMCS through a custom connector, for example: *"Create a Business Hosting group and a 50 GB cPanel package at 9.99 USD/month"*, *"Which invoices are overdue?"* or *"Suspend service #315"*.

```
Claude / ChatGPT  --HTTPS + connector key-->  WHMCS /modules/addons/xmarthost_mcp/mcp.php
                                                 |  permissions, rate limit, audit log
                                                 v
                                   WHMCS API (identifier + secret)  /  Capsule (reports, product edits)
```

## Install

1. `./build.sh` (or copy the folder) and upload `modules/addons/xmarthost_mcp/` to your WHMCS root.
2. WHMCS admin: **System Settings › Addon Modules › XMart Host MCP › Activate**. Under **Configure › Access Control**, tick the admin roles allowed to manage it.
3. Open **Addons › XMart Host MCP**.

Requirements: WHMCS 8.0 or later (9.x included), PHP 7.2 to 8.4 with cURL, HTTPS.

## Configure (3 steps, shown as a checklist on the dashboard)

1. **API Connection**: in WHMCS create an API Role (all permissions, or only what the AI should do) and an API Credential, then paste the **identifier + secret**, click **Save & test**. If WHMCS answers 403, whitelist the server IP under *General Settings › Security › API IP Access Restriction* or enter the API access key. *Internal API* mode (`localAPI()`, no credentials) is available as an alternative.
2. **AI Connectors**: create a connector: name, access level (Read only / Read & write / Full access), the areas it may use (Clients, Billing, Orders, Products, Services, Domains, Support, Reports, Projects, System), optional IP allowlist and expiry. Copy the connector URL. It is shown only once.
3. **Add it to your AI**:
   - **Claude**: Settings › Connectors › Add custom connector › paste the URL.
   - **ChatGPT**: Settings › Apps & Connectors › Advanced › Developer mode, then Create › paste the URL, Authentication: *No authentication*.
   - **Claude Code**: `claude mcp add --transport http xmarthost-whmcs "https://your-whmcs/modules/addons/xmarthost_mcp/mcp.php?key=xmh_..."`
   - **Cursor / VS Code / n8n**: URL `…/mcp.php` with header `Authorization: Bearer xmh_...`.

## Tools

45 typed tools plus `whmcs_api_call`, which runs any of the 162 cataloged WHMCS API actions (and newer ones with Full access). All can be switched on or off under **Tool Management**.

| Area | Tools |
|---|---|
| Overview | `whmcs_overview`, `whmcs_find_actions`, `whmcs_api_call` |
| Clients | `search_clients`, `get_client` (360 view), `create_client`, `update_client` |
| Products | `list_products`, `list_product_groups`, `create_product_group`*, `create_product`, `update_product`* (fields, module settings, pricing per currency), `list_configurable_options`*, `create_configurable_option`* |
| Orders | `list_orders`, `create_order`, `accept_order`, `cancel_order` |
| Services | `list_services`, `service_action` (create/suspend/unsuspend/changepackage/changepassword/terminate), `update_service`, `upgrade_service` |
| Billing | `list_invoices`, `get_invoice`, `create_invoice`, `add_invoice_payment`, `add_credit`, `list_transactions` |
| Domains | `list_domains`, `domain_check`, `tld_pricing`, `domain_action` (register/renew/transfer/nameservers/lock/unlock/epp) |
| Support | `list_tickets`, `get_ticket`, `open_ticket`, `reply_ticket`, `update_ticket`, `add_ticket_note` |
| Reports* | `report_mrr` (MRR/ARR), `report_revenue` (by month and gateway, with fees), `report_top_clients`, `report_aging_invoices`, `report_churn` |
| System | `send_email`, `activity_log` |

\* Not available in the WHMCS API; done through WHMCS's database layer (Capsule), inside transactions, and recorded in the WHMCS activity log.

MCP prompts (slash commands): `daily_briefing`, `client_360`, `overdue_followup`, `new_hosting_package`, `ticket_triage`, `revenue_report`.

## Security

- Connector keys: `xmh_` + 192 random bits, stored only as SHA-256, shown once, optional expiry, revocable one by one or all at once.
- Three access levels: **read**, **write** (no deletes/terminations), **full**. Per-area permissions per connector, per-tool switches and a global blocklist of API actions. The WHMCS API role of the credential limits everything again.
- API secret and access key are encrypted with the WHMCS encryption key.
- HTTPS required; `Origin` header checked (DNS-rebinding protection); global and per-connector IP/CIDR allowlists.
- Rate limit per connector (default 120 tool calls/min); IPs sending unknown keys are locked out for 15 minutes. Revoked keys still configured in an AI app don't trigger the lockout, so a shared Claude/ChatGPT IP is never blocked for valid connectors.
- Audit log of every request: connector, tool, API actions, access level, status, IP, duration and parameters (passwords, keys, card data masked). Pruned by the daily cron after the retention period.
- Admin page: WHMCS addon access control + CSRF tokens on every form, all output escaped.
- The AI is instructed to confirm destructive or customer-facing actions and to treat ticket text as data.

Deactivating the addon disables the endpoint at once; settings and connectors are kept. To remove all data, drop the `mod_xmarthost_mcp_settings`, `mod_xmarthost_mcp_tokens` and `mod_xmarthost_mcp_logs` tables.

## Protocol

MCP Streamable HTTP (JSON responses, no SSE stream, no sessions), protocol versions `2025-06-18`, `2025-03-26` and `2024-11-05`; batches; `tools/*`, `prompts/*`, `ping`. The key is accepted as `Authorization: Bearer`, `X-API-Key`, `mcp.php/<key>` or `?key=`.

## Development

```bash
cd whmcs/tests
composer install      # Laravel database layer + SQLite stand-in for WHMCS
php run.php           # unit tests: auth, permissions, tools, reports, admin page
./e2e.sh              # real mcp.php over HTTP, API-credential mode against a fake api.php
cd .. && ./build.sh   # dist/xmarthost_mcp-<version>.zip
```
