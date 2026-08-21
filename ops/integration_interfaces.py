# -*- coding: utf-8 -*-
"""Small cross-lane interfaces. No implementation or private runtime data lives here."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol, Sequence, Mapping, Any

@dataclass(frozen=True)
class PageRequest:
    limit:int=50; cursor:str|None=None
@dataclass(frozen=True)
class PageResult:
    items:tuple[Mapping[str,Any],...]; next_cursor:str|None=None
@dataclass(frozen=True)
class WritePreview:
    preview_sha256:str; operation_kind:str; target_sha256:str; payload_sha256:str; expires_at:int
@dataclass(frozen=True)
class WriteCommitResult:
    result_code:str; operation_sha256:str
class ReadService(Protocol):
    def list_dialogs(self,page:PageRequest)->PageResult: ...
    def search(self,query:Mapping[str,Any],page:PageRequest)->PageResult: ...
class MediaService(Protocol):
    def metadata(self,file_id_sha256:str)->Mapping[str,Any]: ...
class WriteService(Protocol):
    def preview(self,operation:Mapping[str,Any])->WritePreview: ...
    def commit(self,preview_sha256:str,idempotency_sha256:str)->WriteCommitResult: ...
class RuntimeEvidenceProvider(Protocol):
    def non_secret_identity(self)->Mapping[str,Any]: ...