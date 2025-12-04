from odoo import fields, models


class OAuthDashboard(models.TransientModel):
    _name = "auth_oidc.dashboard"
    _description = "OIDC Dashboard"

    docs_url = fields.Char(default="https://github.com/woehrl/odoo-oidc-provider")
    client_count = fields.Integer(compute="_compute_stats")
    key_count = fields.Integer(compute="_compute_stats")
    scope_count = fields.Integer(compute="_compute_stats")
    event_count = fields.Integer(compute="_compute_stats")
    cron_tokens_active = fields.Boolean(compute="_compute_stats")
    cron_tokens_next = fields.Datetime(compute="_compute_stats")
    cron_codes_active = fields.Boolean(compute="_compute_stats")
    cron_codes_next = fields.Datetime(compute="_compute_stats")

    def _compute_stats(self):
        client_model = self.env["auth_oidc.client"].sudo()
        key_model = self.env["auth_oidc.key"].sudo()
        scope_model = self.env["auth_oidc.scope"].sudo()
        event_model = self.env["auth_oidc.event"].sudo()
        cron_tokens = self.env.ref("odoo_oidc_provider.ir_cron_oidc_cleanup_tokens", raise_if_not_found=False)
        cron_codes = self.env.ref("odoo_oidc_provider.ir_cron_oidc_cleanup_codes", raise_if_not_found=False)
        for record in self:
            record.client_count = client_model.search_count([])
            record.key_count = key_model.search_count([])
            record.scope_count = scope_model.search_count([])
            record.event_count = event_model.search_count([])
            record.cron_tokens_active = bool(cron_tokens and cron_tokens.active)
            record.cron_tokens_next = cron_tokens.nextcall if cron_tokens else False
            record.cron_codes_active = bool(cron_codes and cron_codes.active)
            record.cron_codes_next = cron_codes.nextcall if cron_codes else False

    def action_open_docs(self):
        self.ensure_one()
        return {
            "type": "ir.actions.act_url",
            "target": "new",
            "url": self.docs_url,
        }

    def action_refresh(self):
        self.ensure_one()
        return {
            "type": "ir.actions.act_window",
            "res_model": "auth_oidc.dashboard",
            "view_mode": "form",
            "target": "new",
        }
