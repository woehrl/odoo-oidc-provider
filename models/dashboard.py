from odoo import fields, models


class OAuthDashboard(models.TransientModel):
    _name = "auth_oidc.dashboard"
    _description = "OIDC Dashboard"

    docs_url = fields.Char(default="https://github.com/woehrl/odoo-oidc-provider")
    client_count = fields.Integer(compute="_compute_stats")
    key_count = fields.Integer(compute="_compute_stats")
    scope_count = fields.Integer(compute="_compute_stats")
    event_count = fields.Integer(compute="_compute_stats")

    def _compute_stats(self):
        client_model = self.env["auth_oidc.client"].sudo()
        key_model = self.env["auth_oidc.key"].sudo()
        scope_model = self.env["auth_oidc.scope"].sudo()
        event_model = self.env["auth_oidc.event"].sudo()
        for record in self:
            record.client_count = client_model.search_count([])
            record.key_count = key_model.search_count([])
            record.scope_count = scope_model.search_count([])
            record.event_count = event_model.search_count([])

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
