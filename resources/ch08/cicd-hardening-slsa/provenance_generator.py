"""
provenance_generator.py  —  SLSA v0.2 provenance attestation for ML builds
AI Fortress · Chapter 8 · Code Sample 8.D

Generates SLSA v0.2 provenance attestations for ML model build artefacts.
The provenance statement records how an artefact was produced, enabling
consumers to verify it was built from trusted source code by a trusted builder.

SLSA v0.2 spec: https://slsa.dev/provenance/v0.2
in-toto statement spec: https://github.com/in-toto/attestation

Output format: in-toto Statement wrapping SLSA Provenance predicate (JSON).
Can be signed with cosign or stored in a transparency log (Rekor).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class BuildSubject:
    """A build output artefact described in the provenance."""
    name:   str
    sha256: str
    uri:    str = ""     # e.g. registry URI or S3 path


@dataclass
class SLSAProvenance:
    statement_type:  str = "https://in-toto.io/Statement/v0.1"
    predicate_type:  str = "https://slsa.dev/provenance/v0.2"
    subjects:        List[BuildSubject]         = field(default_factory=list)
    builder_id:      str = ""
    build_type:      str = "https://github.com/Attestations/GitHubActionsWorkflow@v1"
    invocation:      dict = field(default_factory=dict)
    build_config:    dict = field(default_factory=dict)
    metadata:        dict = field(default_factory=dict)
    materials:       List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "_type":         self.statement_type,
            "predicateType": self.predicate_type,
            "subject":       [
                {"name": s.name, "digest": {"sha256": s.sha256}, "uri": s.uri}
                for s in self.subjects
            ],
            "predicate": {
                "builder":     {"id": self.builder_id},
                "buildType":   self.build_type,
                "invocation":  self.invocation,
                "buildConfig": self.build_config,
                "metadata":    self.metadata,
                "materials":   self.materials,
            },
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


class ProvenanceGenerator:
    """
    Generates SLSA v0.2 provenance attestations for ML build outputs.

    Parameters
    ----------
    builder_id  : URI identifying the build system (e.g. GitHub Actions runner)
    """

    def __init__(self, builder_id: str = "https://github.com/actions/runner"):
        self.builder_id = builder_id

    def generate(
        self,
        subjects:        List[BuildSubject],
        source_repo:     str,
        source_ref:      str,                   # branch or tag
        source_sha:      str,                   # commit SHA
        workflow_path:   str = "",              # .github/workflows/train.yml
        trigger:         str = "push",          # push | pull_request | schedule
        build_params:    Optional[dict] = None,
        environment:     Optional[dict] = None,
    ) -> SLSAProvenance:
        """
        Generate a SLSA provenance statement for the given build subjects.

        Parameters
        ----------
        subjects      : List of BuildSubject (output artefacts)
        source_repo   : Source repository URI
        source_ref    : Git ref (branch or tag)
        source_sha    : Full git commit SHA (40 hex chars)
        workflow_path : Path to the CI workflow file
        trigger       : Build trigger event
        build_params  : Key/value build parameters (hyperparameters, etc.)
        environment   : Sanitised environment variables (no secrets)
        """
        now = datetime.now(timezone.utc).isoformat()

        invocation = {
            "configSource": {
                "uri":        source_repo,
                "digest":     {"sha1": source_sha},
                "entryPoint": workflow_path,
            },
            "parameters": build_params or {},
            "environment": environment or {},
        }

        metadata = {
            "buildInvocationId": str(uuid.uuid4()),
            "buildStartedOn":    now,
            "completeness": {
                "parameters":  bool(build_params),
                "environment": bool(environment),
                "materials":   True,
            },
            "reproducible": False,
        }

        materials = [
            {
                "uri":    source_repo,
                "digest": {"sha1": source_sha, "ref": source_ref},
            }
        ]

        return SLSAProvenance(
            subjects     = subjects,
            builder_id   = self.builder_id,
            invocation   = invocation,
            metadata     = metadata,
            materials    = materials,
        )

    @staticmethod
    def subject_from_file(path: str | Path, name: Optional[str] = None) -> BuildSubject:
        """Create a BuildSubject by hashing a local file."""
        path = Path(path)
        h    = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return BuildSubject(
            name   = name or path.name,
            sha256 = h.hexdigest(),
            uri    = str(path.resolve()),
        )
