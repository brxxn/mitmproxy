from __future__ import annotations
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

import json
import logging
import os
import re
import secrets
import webbrowser

from mitmproxy import command
from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy.tools.console.interact.types import interact_rule_from_json, InteractAction, InteractRule

if TYPE_CHECKING:
    from mitmproxy.tools.console.master import ConsoleMaster

logger = logging.getLogger(__name__)

class InteractAddon:

    def __init__(self, master: ConsoleMaster) -> None:
        self.master = master
        self.rules = []
    
    def load(self, loader):
        loader.add_option('interact_server_host', str, 'localhost', 'server port that interact runs on')
        loader.add_option('interact_server_port', int, 3032, 'server port that interact runs on')
        loader.add_option('interact_rules', Sequence[str], [], 'rules that interact uses (stored in json)')
        loader.add_option('interact_debug', bool, False, 'puts the interact server in debug mode')
        loader.add_option('interact_auth_token', str, secrets.token_urlsafe(256), 'authentication token')
    
    def get_rules(self) -> list[InteractRule]:
        return [interact_rule_from_json(a) for a in self.master.options.interact_rules]

    def get_attribute_for_flow(self, flow: http.HTTPFlow, attribute: str) -> str:
        if attribute == 'request_url':
            return flow.request.url
        elif attribute == 'request_host':
            return flow.request.host
        elif attribute == 'request_body':
            return flow.request.content.decode()
        elif attribute == 'response_status_code' and flow.response:
            return str(flow.response.status_code)
        elif attribute == 'response_content_type' and flow.response:
            return flow.response.headers.get('content-type', 'unknown')
        elif attribute == 'response_body' and flow.response:
            return flow.response.content.decode()
        
        return '[unknown]'
    
    def validate_condition(self, operator: str, a: str, b: str) -> bool:
        if operator == 'is':
            return a == b
        elif operator == 'is_ignore_case':
            return a.lower() == b.lower()
        elif operator == 'contains':
            return b in a
        elif operator == 'contains_ignore_case':
            return b.lower() in a.lower()
        elif operator == 'matches_regex':
            return re.match(b, a)
        elif operator == 'matches_regex_ignore_case':
            return re.match(b, a.lower())

        return False
    
    def meets_conditions(self, flow: http.HTTPFlow, rule: InteractRule) -> bool:
        for condition in rule.conditions:
            input_value = self.get_attribute_for_flow(flow, condition.type)
            meets_condition = self.validate_condition(condition.operator, input_value, condition.value)
            if meets_condition and not rule.all_conditions_required:
                return True
            elif not meets_condition and rule.all_conditions_required:
                return False
        return rule.all_conditions_required
    
    def perform_action(self, flow: http.HTTPFlow, action: InteractAction):
        response_action_types = ['set_response_body', 'set_response_status', 'set_response_header', 'replace_response_body']
        if not flow.response and action.type in response_action_types:
            logger.error(f'attempted to use action {response_action_types} when response is not available')
            return

        if action.type == 'set_request_url':
            flow.request.url = action.arguments['url']
        elif action.type == 'set_request_body':
            flow.request.content = action.arguments['body'].encode()
        elif action.type == 'set_request_header':
            flow.request.headers.pop(action.arguments['name'], None)
            flow.request.headers.add(action.arguments['name'], action.arguments['value'])
        elif action.type == 'set_request_method':
            flow.request.method = action.arguments['method']
        elif action.type == 'set_response_body':
            flow.response.content = action.arguments['body'].encode()
        elif action.type == 'set_response_header':
            flow.response.headers.pop(action.arguments['name'], None)
            flow.response.headers.add(action.arguments['name'], action.arguments['value'])
        elif action.type == 'set_response_status':
            flow.response.status_code = int(action.arguments['status'])
        elif action.type == 'replace_request_url':
            flow.request.url = re.sub(action.arguments['regex'], action.arguments['value'], flow.request.url)
        elif action.type == 'replace_request_body':
            request_body = flow.request.content.decode()
            request_body = re.sub(action.arguments['regex'], action.arguments['value'], request_body)
            flow.request.content = request_body.encode()
        elif action.type == 'replace_response_body':
            response_body = flow.response.content.decode()
            response_body = re.sub(action.arguments['regex'], action.arguments['value'], response_body)
            flow.response.content = response_body.encode()


    def perform_actions(self, flow: http.HTTPFlow, rule: InteractRule):
        for action in rule.actions:
            self.perform_action(flow, action)

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.error:
            return
        
        rules = [rule for rule in self.get_rules() if rule.type == 'request' and rule.enabled]
        
        for rule in rules:
            if not self.meets_conditions(flow, rule):
                continue
            self.perform_actions(flow, rule)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.error or not flow.live:
            return
        rules = [rule for rule in self.get_rules() if rule.type == 'response' and rule.enabled]
        
        for rule in rules:
            if not self.meets_conditions(flow, rule):
                continue
            self.perform_actions(flow, rule)
    
    @command.command('interact.open')
    def open_interact_panel(self):
        host = self.master.options.interact_server_host
        port = self.master.options.interact_server_port
        token = self.master.options.interact_auth_token
        url = f'http://{host}:{port}/authenticate?token={token}'
        if not webbrowser.open(url):
            raise exceptions.CommandError(f'failed to open browser, please manually visit {url} to open the panel')
    
    @command.command('interact.export')
    def export_rules(self, file: str):
        try:
            Path(file).expanduser().touch()
            Path(file).expanduser().write_text(json.dumps(self.master.options.interact_rules))
        except OSError as e:
            raise exceptions.CommandError(f'Could not write to file {file}, received error: {e}')
        
    @command.command('interact.import')
    def import_rules(self, file: str):
        try:
            data = Path(file).expanduser().read_text()
            option_value = json.loads(data)
            setattr(
                self.master.options,
                'interact_rules',
                option_value
            )
        except OSError as e:
            raise exceptions.CommandError(f'Could not read file {file}, received error: {e}')
        
