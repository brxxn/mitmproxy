from __future__ import annotations
from pathlib import Path
import json
import os
import tornado.web

from mitmproxy.tools.console.interact.types import InteractAction, InteractCondition, InteractRule, interact_rule_from_json

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from mitmproxy.tools.console.master import ConsoleMaster

class APIError(tornado.web.HTTPError):
    pass

class Application(tornado.web.Application):

    def __init__(self, master: ConsoleMaster) -> None:
        self.master = master
        super().__init__(
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            serve_traceback=self.master.options.interact_debug
        )

        self.add_handlers(
            r'.*',
            [
                (r'/v1/rules', RulesHandler),
                (r'/v1/rules/delete', DeleteRuleHandler),
                (r'/v1/rules/delete-all', DeleteAllRulesHandler),
                (r'/v1/backup/import', BackupImportHandler),
                (r'/v1/backup/export', BackupExportHandler),
                (r'^/(?!static).*$', IndexHandler)
            ]
        )

    def get_interact_rules(self) -> list[InteractRule] :
        return [interact_rule_from_json(a) for a in self.master.options.interact_rules]
    
    def save_interact_rules(self, rules: list[InteractRule]) -> list[InteractRule]:
        interact_rule_strings = [a.to_json() for a in rules]
        setattr(
            self.master.options,
            'interact_rules',
            interact_rule_strings
        )
        return sorted(self.get_interact_rules(), key=lambda r: r.name)
    
    def import_rules(self, filename: str) -> bool:
        try:
            data = Path(filename).expanduser().read_text()
            option_value = json.loads(data)
            setattr(
                self.master.options,
                'interact_rules',
                option_value
            )
            return True
        except OSError:
            return False
    
    def export_rules(self, filename: str) -> bool:
        try:
            Path(filename).expanduser().touch()
            Path(filename).expanduser().write_text(json.dumps(self.master.options.interact_rules))
            return True
        except OSError:
            return False
    
    def get_interact_rule(self, name: str) -> InteractRule|None:
        rules = self.get_interact_rules(name)
        target_rule = [a for a in rules if a.name == name]
        return target_rule[0] if len(target_rule) > 0 else None
    
    def add_or_update_rule(self, rule: InteractRule) -> list[InteractRule]:
        rules = self.get_interact_rules()
        updated_rules = [a for a in rules if a.name != rule.name]
        updated_rules.append(rule)
        return self.save_interact_rules(updated_rules)
    
    def delete_rule(self, rule: InteractRule) -> list[InteractRule]:
        rules = self.get_interact_rules()
        updated_rules = [a for a in rules if a.name != rule.name]
        return self.save_interact_rules(updated_rules)

def require_auth(func):
    def wrapper(self: RequestHandler, *args, **kwargs):
        if self.request.headers.get('authorization') is None:
            self.set_status(401)
            self.write({'error': 'no authorization header'})
            return
        if self.request.headers.get('authorization') != self.application.master.options.interact_auth_token:
            self.set_status(403)
            self.write({'error': 'invalid auth header'})
            return
        func(self)
    return wrapper

# stolen from web
class RequestHandler(tornado.web.RequestHandler):
    application: Application

    def write(self, chunk: str | bytes | dict | list):
        # Writing arrays on the top level is ok nowadays.
        # http://flask.pocoo.org/docs/0.11/security/#json-security
        if isinstance(chunk, list):
            chunk = tornado.escape.json_encode(chunk)
            self.set_header("Content-Type", "application/json; charset=UTF-8")
        super().write(chunk)

    def set_default_headers(self):
        super().set_default_headers()
        self.set_header("X-Frame-Options", "DENY")
        self.add_header("X-XSS-Protection", "1; mode=block")
        self.add_header("X-Content-Type-Options", "nosniff")

    @property
    def json(self):
        if not self.request.headers.get("Content-Type", "").startswith(
            "application/json"
        ):
            raise APIError(400, "Invalid Content-Type, expected application/json.")
        try:
            return json.loads(self.request.body.decode())
        except Exception as e:
            raise APIError(400, f"Malformed JSON: {str(e)}")

    @property
    def filecontents(self):
        """
        Accept either a multipart/form file upload or just take the plain request body.

        """
        if self.request.files:
            return next(iter(self.request.files.values()))[0].body
        else:
            return self.request.body

    def write_error(self, status_code: int, **kwargs):
        if "exc_info" in kwargs and isinstance(kwargs["exc_info"][1], APIError):
            self.finish(kwargs["exc_info"][1].log_message)
        else:
            super().write_error(status_code, **kwargs)

class IndexHandler(RequestHandler):
    def get(self):
        self.render('index.html')

class RulesHandler(RequestHandler):

    @require_auth
    def get(self):
        self.write({'rules':[a.to_dict() for a in self.application.get_interact_rules()]})

    @require_auth
    def post(self):
        rule = interact_rule_from_json(json.dumps(self.json['rule']))
        self.write({'rules':[a.to_dict() for a in self.application.add_or_update_rule(rule)]})

class DeleteRuleHandler(RequestHandler):

    @require_auth
    def post(self):
        rule = interact_rule_from_json(json.dumps(self.json['rule']))
        self.write({'rules':[a.to_dict() for a in self.application.delete_rule(rule)]})

class DeleteAllRulesHandler(RequestHandler):

    @require_auth
    def post(self):
        self.write({'rules':[a.to_dict() for a in self.application.save_interact_rules([])]})

class BackupImportHandler(RequestHandler):

    @require_auth
    def post(self):
        filename = self.json['filename']
        success = self.application.import_rules(filename)
        if not success:
            self.set_status(400)
        self.write({'rules':[a.to_dict() for a in self.application.get_interact_rules()]})

class BackupExportHandler(RequestHandler):

    @require_auth
    def post(self):
        filename = self.json['filename']
        success = self.application.export_rules(filename)
        if not success:
            self.set_status(400)
        self.write({'success': success})
