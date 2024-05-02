import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import http
from mitmproxy.utils import strutils

logger = logging.getLogger(__name__)

class ReplaceResponseDict(NamedTuple):
    path: str
    replacement: str
    replacement_is_file: bool

    def read(self) -> bytes:
        if not self.replacement_is_file:
            return strutils.escaped_str_to_bytes(self.replacement)
        
        return Path(self.replacement).expanduser().read_bytes()

    def to_json(self) -> str:
        return json.dumps({
            'path': self.path,
            'replacement': self.replacement,
            'replacement_is_file': self.replacement_is_file
        })

def parse_replace_response_spec(option: str) -> ReplaceResponseDict:
    json_parsed_option: dict = json.loads(option)
    
    path = json_parsed_option.get('path')
    replacement = json_parsed_option.get('replacement')
    replacement_is_file = json_parsed_option.get('replacement_is_file', False)

    if path is None or replacement is None:
        raise ValueError(f'Invalid replace-response object: {option}')
    
    spec = ReplaceResponseDict(path, replacement, replacement_is_file)

    try:
        spec.read()
    except OSError as oe:
        raise ValueError(f"Could not read replace-response file: {replacement} ({oe})")

    return spec


class ReplaceResponse:

    def __init__(self) -> None:
        self.replacements: list[ReplaceResponseDict] = []
    
    def add_replacement(self, path: str, content: str, is_file: bool):
        replacement_dict = {
            'path': path,
            'replacement': content,
            'replacement_is_file': is_file
        }
        replacement_str = json.dumps(replacement_dict)
        self.remove_replacement(path)
        setattr(
            ctx.options,
            'replace_response_body',
            ctx.options.replace_response_body + [replacement_str]
        )

    def remove_replacement(self, path: str):
        current_replacements = self.replacements
        removing_replacements = [replacement for replacement in current_replacements if replacement.path == path]
        for replacement in removing_replacements:
            current_replacements.remove(replacement)
        replacement_strs = [replacement.to_json() for replacement in current_replacements]
        setattr(
            ctx.options,
            'replace_response_body',
            replacement_strs
        )

    def load(self, loader):
        loader.add_option(
            "replace_response_body",
            Sequence[str],
            [],
            "Quickly replaces response body for any request"
        )

    def configure(self, updated):
        if "replace_response_body" in updated:
            self.replacements = []
            for replacement_opt in ctx.options.replace_response_body:
                try:
                    replacement = parse_replace_response_spec(replacement_opt)
                except ValueError as e:
                    raise exceptions.OptionsError(f'Cannot parse replace_response_body option: {replacement_opt} ({e})')
                self.replacements.append(replacement)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.error or not flow.live:
            return
        
        for replacement in self.replacements:
            if flow.request.url == replacement.path:
                replacement_bytes = replacement.read()
                # may need to figure out how to set content-length header
                flow.response.content = replacement_bytes
    
    @command.command('replace.body.file')
    def add_file_replacement(self, file: str, flow: flow.Flow):
        '''
        Replace all future responses to a path with a file
        '''
        try:
            Path(file).expanduser().read_bytes()
        except OSError as e:
            raise exceptions.CommandError(f'Could not read file {file}, received error: {e}')
        assert isinstance(flow, http.HTTPFlow)
        self.add_replacement(flow.request.url, file, True)
        logger.info(f'Added file replacement for {flow.request.url}')

    @command.command('replace.body.content')
    def add_content_replacement(self, content: str, flow: flow.Flow):
        '''
        Replace all future responses to a path with a file
        '''
        assert isinstance(flow, http.HTTPFlow)
        self.add_replacement(flow.request.url, content, False)
        logger.info(f'Added content replacement for {flow.request.url}')

    @command.command('replace.body.edit')
    def add_str_replacement(self, flow: flow.Flow):
        '''
        Open an editor to edit future responses to this path
        '''
        assert isinstance(flow, http.HTTPFlow)
        # hopefully this doesnt get run outside of console
        # assert isinstance(ctx.master, ConsoleMaster)
        editor_text = b''
        existing_replacements = [replacement for replacement in self.replacements if replacement.path == flow.request.url]
        if len(existing_replacements) != 0:
            if existing_replacements[0].replacement_is_file:
                editor_text = Path(self.replacement).expanduser().read_bytes()
            else:
                editor_text = existing_replacements[0].replacement.encode()
        if editor_text == b'' and flow.response:
            editor_text = flow.response.content
        edited_body = ctx.master.spawn_editor(editor_text)
        self.add_replacement(flow.request.url, edited_body.decode(), False)
        logger.info(f'Updated replacement for {flow.request.url}')
    
    @command.command('replace.body.remove')
    def clear_replacement(self, flow: flow.Flow):
        '''
        Remove any replacements on a path
        '''
        assert isinstance(flow, http.HTTPFlow)
        self.remove_replacement(flow.request.url)
        logger.info(f'Removed replacement for {flow.request.url}')

    @command.command('replace.body.clearall')
    def clear_all_replacements(self):
        '''
        Clears all replacements
        '''
        replacement_count = len(self.replacements)
        setattr(
            ctx.options,
            'replace_response_body',
            []
        )
        logging.info(f'Cleared {replacement_count} replacements')
