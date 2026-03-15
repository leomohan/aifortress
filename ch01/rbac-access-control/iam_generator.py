"""
iam_generator.py  —  Generate AWS IAM policies from role definitions
AI Fortress · Chapter 1 · Code Sample 1.B

Translates the internal RBAC role definitions into least-privilege AWS IAM
policy JSON documents, one per role, ready for `aws iam create-policy`.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, List
import click
from roles import Role, Classification, load_roles

# Map internal actions → AWS S3 IAM actions
ACTION_MAP: Dict[str, List[str]] = {
    "read":   ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging"],
    "write":  ["s3:PutObject", "s3:PutObjectTagging", "s3:AbortMultipartUpload"],
    "list":   ["s3:ListBucket", "s3:ListBucketVersions", "s3:ListMultipartUploadParts"],
    "delete": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
    "*":      ["s3:*"],
}

# Map internal resource prefix patterns → ARN patterns
def _prefix_to_arn(prefix: str, bucket: str) -> str:
    """Convert s3://*/raw/ style prefix to ARN for a specific bucket."""
    if prefix == "*":
        return f"arn:aws:s3:::{bucket}/*"
    # Strip s3://*/ and replace with bucket ARN
    path = prefix.replace("s3://*/", "").rstrip("/")
    if path:
        return f"arn:aws:s3:::{bucket}/{path}/*"
    return f"arn:aws:s3:::{bucket}/*"


def generate_iam_policy(role: Role, bucket: str) -> dict:
    """Generate a least-privilege IAM policy document for a role."""
    statements = []

    # Collect all IAM actions this role needs
    iam_actions: List[str] = []
    for action in role.allowed_actions:
        iam_actions.extend(ACTION_MAP.get(action, [f"s3:{action.capitalize()}Object"]))
    iam_actions = sorted(set(iam_actions))

    # Resource ARNs
    resources = [_prefix_to_arn(p, bucket) for p in role.allowed_resource_prefixes]
    # Also need ListBucket at the bucket level (not object level)
    bucket_arns = [f"arn:aws:s3:::{bucket}"]

    if any(a.startswith("s3:List") for a in iam_actions):
        statements.append({
            "Sid":      f"{_sid(role.name)}ListBucket",
            "Effect":   "Allow",
            "Action":   [a for a in iam_actions if "List" in a],
            "Resource": bucket_arns,
        })
        object_actions = [a for a in iam_actions if "List" not in a]
    else:
        object_actions = iam_actions

    if object_actions:
        statements.append({
            "Sid":      f"{_sid(role.name)}ObjectAccess",
            "Effect":   "Allow",
            "Action":   object_actions,
            "Resource": resources,
        })

    # Deny access above classification ceiling
    if role.classification_ceiling < Classification.RESTRICTED:
        deny_tags = [
            cl.name for cl in Classification
            if cl > role.classification_ceiling
        ]
        statements.append({
            "Sid":    f"{_sid(role.name)}DenyHighClassification",
            "Effect": "Deny",
            "Action": ["s3:GetObject"],
            "Resource": [f"arn:aws:s3:::{bucket}/*"],
            "Condition": {
                "StringEqualsIfExists": {
                    "s3:ExistingObjectTag/Classification": deny_tags
                }
            },
        })

    return {
        "Version": "2012-10-17",
        "Statement": statements,
    }


def _sid(role_name: str) -> str:
    """Convert role name to PascalCase SID prefix."""
    return "".join(w.capitalize() for w in role_name.replace("-", " ").split())


@click.command()
@click.option("--roles-config", default="config/roles.yaml", show_default=True)
@click.option("--bucket",       required=True, help="S3 bucket name")
@click.option("--output-dir",   default="./iam-policies", show_default=True)
def generate(roles_config, bucket, output_dir):
    """Generate least-privilege IAM policy JSON files for all defined roles."""
    roles = load_roles(roles_config)
    out   = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    for name, role in roles.items():
        policy  = generate_iam_policy(role, bucket)
        outfile = out / f"{name}.json"
        outfile.write_text(json.dumps(policy, indent=2))
        click.echo(f"  ✓ {outfile}")

    click.secho(f"\nGenerated {len(roles)} IAM policies in {out}/", fg="green")
    click.echo("Deploy with:")
    click.echo(f"  aws iam create-policy --policy-name AIFortress-<role> \\")
    click.echo(f"    --policy-document file://{out}/<role>.json")


if __name__ == "__main__":
    generate()
