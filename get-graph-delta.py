#!/usr/bin/env python3
"""Code Graph Delta Extractor for the k8s-pre-release-auditor skill.

Reads `helm template` output (YAML stream) from stdin or --file, extracts only
the fields the auditor skill needs, diffs them against a local SQLite topology
snapshot, and emits a minimal JSON delta payload on stdout.

Intended to be driven by a git pre-push hook:

    helm template ./charts/foo | ./get-graph-delta.py | <ai-cli> --skill k8s-pre-release-auditor

Note: the snapshot lives in its own database file, NOT in codegraph.db, which
already owns `nodes`/`edges` tables for the source-code index.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write("error: PyYAML is required (pip install PyYAML)\n")
    raise SystemExit(2)

DEFAULT_DB = os.path.join(".codegraph", "k8s-topology.db")

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
SCALER_KINDS = {"HorizontalPodAutoscaler", "ScaledObject"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id      TEXT PRIMARY KEY,
    kind    TEXT NOT NULL,
    name    TEXT NOT NULL,
    hash    TEXT NOT NULL,
    details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS nodes_kind_idx ON nodes (kind);
"""


# --------------------------------------------------------------------------
# Module 1: database
# --------------------------------------------------------------------------
def open_db(path, reset=False):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    if reset:
        conn.execute("DELETE FROM nodes")
        conn.commit()
    return conn


def load_hashes(conn):
    return {row[0]: row[1] for row in conn.execute("SELECT id, hash FROM nodes")}


def save_nodes(conn, nodes):
    conn.executemany(
        "INSERT OR REPLACE INTO nodes (id, kind, name, hash, details) VALUES (?, ?, ?, ?, ?)",
        [
            (n["id"], n["kind"], n["name"], n["hash"], json.dumps(n["details"], sort_keys=True))
            for n in nodes
        ],
    )
    conn.commit()


# --------------------------------------------------------------------------
# Module 2: YAML parsing and feature extraction
# --------------------------------------------------------------------------
def dig(obj, *keys, default=None):
    """Safe nested lookup that tolerates None and non-dict values."""
    cur = obj
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return default if cur is None else cur


def extract_container(container):
    """Keep only the container fields the audit rules reason about."""
    resources = dig(container, "resources", default={})
    requests = resources.get("requests") or {}
    limits = resources.get("limits") or {}
    security = container.get("securityContext") or {}

    out = {
        "name": container.get("name"),
        "image": container.get("image"),
        "cpu_request": requests.get("cpu"),
        "cpu_limit": limits.get("cpu"),
        "memory_request": requests.get("memory"),
        "memory_limit": limits.get("memory"),
    }

    if security:
        out["securityContext"] = {
            k: security[k]
            for k in (
                "privileged",
                "allowPrivilegeEscalation",
                "runAsNonRoot",
                "runAsUser",
                "readOnlyRootFilesystem",
                "capabilities",
            )
            if k in security
        }

    ports = container.get("ports") or []
    if ports:
        out["ports"] = [
            {"name": p.get("name"), "containerPort": p.get("containerPort")}
            for p in ports
            if isinstance(p, dict)
        ]

    probes = {}
    for probe_name in ("livenessProbe", "readinessProbe", "startupProbe"):
        probe = container.get(probe_name)
        if isinstance(probe, dict):
            port = dig(probe, "httpGet", "port") or dig(probe, "tcpSocket", "port")
            if port is not None:
                probes[probe_name] = port
    if probes:
        out["probe_ports"] = probes

    mounts = container.get("volumeMounts") or []
    if mounts:
        out["volume_mounts"] = [
            {"name": m.get("name"), "mountPath": m.get("mountPath")}
            for m in mounts
            if isinstance(m, dict)
        ]

    return {k: v for k, v in out.items() if v is not None}


def pod_spec_of(doc, kind):
    """Locate the PodSpec for a workload, including the CronJob extra nesting."""
    if kind == "CronJob":
        return dig(doc, "spec", "jobTemplate", "spec", "template", "spec", default={}), dig(
            doc, "spec", "jobTemplate", "spec", "template", "metadata", "labels", default={}
        )
    return (
        dig(doc, "spec", "template", "spec", default={}),
        dig(doc, "spec", "template", "metadata", "labels", default={}),
    )


def extract_workload(doc, kind):
    pod_spec, pod_labels = pod_spec_of(doc, kind)
    containers = [
        extract_container(c) for c in (pod_spec.get("containers") or []) if isinstance(c, dict)
    ]
    init_containers = [
        extract_container(c) for c in (pod_spec.get("initContainers") or []) if isinstance(c, dict)
    ]

    details = {
        "apiVersion": doc.get("apiVersion"),
        "labels": dig(doc, "metadata", "labels", default={}),
        "pod_labels": pod_labels,
        "replicas": dig(doc, "spec", "replicas"),
        "containers": containers,
    }
    if init_containers:
        details["init_containers"] = init_containers

    for field in ("hostNetwork", "hostIPC", "hostPID"):
        if pod_spec.get(field):
            details[field] = True

    pod_security = pod_spec.get("securityContext") or {}
    if pod_security:
        details["pod_securityContext"] = pod_security
    if pod_spec.get("serviceAccountName"):
        details["serviceAccountName"] = pod_spec["serviceAccountName"]
    if pod_spec.get("serviceAccount"):
        details["serviceAccount_deprecated"] = pod_spec["serviceAccount"]

    host_paths = [
        {"name": v.get("name"), "path": dig(v, "hostPath", "path")}
        for v in (pod_spec.get("volumes") or [])
        if isinstance(v, dict) and v.get("hostPath")
    ]
    if host_paths:
        details["host_path_volumes"] = host_paths

    details["has_pod_anti_affinity"] = bool(dig(pod_spec, "affinity", "podAntiAffinity"))
    if dig(pod_spec, "affinity", "podAntiAffinity"):
        details["podAntiAffinity"] = dig(pod_spec, "affinity", "podAntiAffinity")

    return details


def extract_service(doc):
    return {
        "apiVersion": doc.get("apiVersion"),
        "type": dig(doc, "spec", "type"),
        "selector": dig(doc, "spec", "selector", default={}),
        "ports": [
            {
                "name": p.get("name"),
                "port": p.get("port"),
                "targetPort": p.get("targetPort"),
                "protocol": p.get("protocol"),
            }
            for p in (dig(doc, "spec", "ports", default=[]) or [])
            if isinstance(p, dict)
        ],
    }


def extract_scaler(doc):
    ref = dig(doc, "spec", "scaleTargetRef", default={})
    details = {
        "apiVersion": doc.get("apiVersion"),
        "scaleTargetRef": {
            # KEDA ScaledObject defaults kind to Deployment when omitted.
            "kind": ref.get("kind") or "Deployment",
            "name": ref.get("name"),
            "apiVersion": ref.get("apiVersion"),
        },
    }
    for field in ("minReplicas", "maxReplicas", "minReplicaCount", "maxReplicaCount"):
        value = dig(doc, "spec", field)
        if value is not None:
            details[field] = value
    return details


def extract_pdb(doc):
    return {
        "apiVersion": doc.get("apiVersion"),
        "minAvailable": dig(doc, "spec", "minAvailable"),
        "maxUnavailable": dig(doc, "spec", "maxUnavailable"),
        "unhealthyPodEvictionPolicy": dig(doc, "spec", "unhealthyPodEvictionPolicy"),
        "selector": dig(doc, "spec", "selector", "matchLabels", default={}),
    }


def extract(doc):
    """Return (kind, details) for an audited resource, or None to drop it."""
    kind = doc.get("kind")
    if kind in WORKLOAD_KINDS:
        return extract_workload(doc, kind)
    if kind in ("Service",):
        return extract_service(doc)
    if kind in SCALER_KINDS:
        return extract_scaler(doc)
    if kind == "PodDisruptionBudget":
        return extract_pdb(doc)
    if kind == "Pod":
        containers = [
            extract_container(c)
            for c in (dig(doc, "spec", "containers", default=[]) or [])
            if isinstance(c, dict)
        ]
        return {
            "apiVersion": doc.get("apiVersion"),
            "labels": dig(doc, "metadata", "labels", default={}),
            "pod_labels": dig(doc, "metadata", "labels", default={}),
            "containers": containers,
        }
    return None


def prune(value):
    """Drop None / empty values so the hash is stable and the payload is small."""
    if isinstance(value, dict):
        return {k: prune(v) for k, v in value.items() if v is not None and prune(v) != {}}
    if isinstance(value, list):
        return [prune(v) for v in value]
    return value


def node_id(doc):
    meta = doc.get("metadata") or {}
    name = meta.get("name") or "<unnamed>"
    namespace = meta.get("namespace")
    base = "%s/%s" % (doc.get("kind"), name)
    return "%s/%s" % (base, namespace) if namespace else base, name, namespace


def build_nodes(stream):
    """Parse a multi-document YAML stream into hashed topology nodes."""
    nodes = {}
    for doc in yaml.safe_load_all(stream):
        if not isinstance(doc, dict) or not doc.get("kind"):
            continue
        details = extract(doc)
        if details is None:
            continue
        details = prune(details)
        nid, name, namespace = node_id(doc)
        payload = json.dumps(details, sort_keys=True, separators=(",", ":"))
        nodes[nid] = {
            "id": nid,
            "kind": doc["kind"],
            "name": name,
            "namespace": namespace,
            "hash": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "details": details,
        }
    return nodes


# --------------------------------------------------------------------------
# Module 3: delta computation and impact analysis
# --------------------------------------------------------------------------
def selector_matches(selector, labels):
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def compute_edges(nodes):
    """Derive topology edges on the fly from labels, selectors and target refs."""
    edges = []
    workloads = [n for n in nodes.values() if n["kind"] in WORKLOAD_KINDS or n["kind"] == "Pod"]

    def same_namespace(a, b):
        return a.get("namespace") == b.get("namespace")

    for node in nodes.values():
        if node["kind"] == "Service":
            selector = node["details"].get("selector") or {}
            targets = [
                w
                for w in workloads
                if same_namespace(node, w)
                and selector_matches(selector, w["details"].get("pod_labels") or {})
            ]
            if targets:
                for target in targets:
                    edges.append(
                        {
                            "relation": "%s -> selects -> %s" % (node["id"], target["id"]),
                            "source": node["id"],
                            "target": target["id"],
                            "type": "selects",
                            "service_selector": selector,
                            "service_ports": node["details"].get("ports") or [],
                            "target_pod_labels": target["details"].get("pod_labels") or {},
                        }
                    )
            else:
                edges.append(
                    {
                        "relation": "%s -> selects -> <no matching workload>" % node["id"],
                        "source": node["id"],
                        "target": None,
                        "type": "dangling_service",
                        "service_selector": selector,
                    }
                )

        elif node["kind"] in SCALER_KINDS:
            ref = node["details"].get("scaleTargetRef") or {}
            target = next(
                (
                    w
                    for w in workloads
                    if w["kind"] == ref.get("kind")
                    and w["name"] == ref.get("name")
                    and same_namespace(node, w)
                ),
                None,
            )
            edges.append(
                {
                    "relation": "%s -> scales -> %s"
                    % (node["id"], target["id"] if target else "<missing target>"),
                    "source": node["id"],
                    "target": target["id"] if target else None,
                    "type": "scales" if target else "dangling_scale_target",
                    "scaleTargetRef": ref,
                }
            )

        elif node["kind"] == "PodDisruptionBudget":
            selector = node["details"].get("selector") or {}
            targets = [
                w
                for w in workloads
                if same_namespace(node, w)
                and selector_matches(selector, w["details"].get("pod_labels") or {})
            ]
            if targets:
                for target in targets:
                    edges.append(
                        {
                            "relation": "%s -> protects -> %s" % (node["id"], target["id"]),
                            "source": node["id"],
                            "target": target["id"],
                            "type": "protects",
                            "pdb_selector": selector,
                        }
                    )
            else:
                edges.append(
                    {
                        "relation": "%s -> protects -> <no matching workload>" % node["id"],
                        "source": node["id"],
                        "target": None,
                        "type": "dangling_pdb",
                        "pdb_selector": selector,
                    }
                )
    return edges


def compute_delta(nodes, known_hashes, audit_all=False):
    """Return (changed_ids, impacted_edges) after one hop of impact expansion."""
    edges = compute_edges(nodes)

    if audit_all:
        return set(nodes), edges

    changed = {
        nid for nid, node in nodes.items() if known_hashes.get(nid) != node["hash"]
    }

    # Impact analysis: pull in the neighbour on any edge touching a changed node,
    # so a renamed label surfaces together with the Service that points at it.
    impacted_edges = []
    neighbours = set()
    for edge in edges:
        endpoints = {edge["source"], edge["target"]} - {None}
        if endpoints & changed:
            impacted_edges.append(edge)
            neighbours |= endpoints

    return changed | neighbours, impacted_edges


# --------------------------------------------------------------------------
# Module 4: payload generation
# --------------------------------------------------------------------------
def build_payload(nodes, delta_ids, impacted_edges, scope):
    changed_nodes = []
    for nid in sorted(delta_ids):
        node = nodes.get(nid)
        if node is None:
            continue
        entry = {"id": node["id"], "kind": node["kind"], "name": node["name"]}
        if node.get("namespace"):
            entry["namespace"] = node["namespace"]
        entry["details"] = node["details"]
        changed_nodes.append(entry)

    return {
        "audit_scope": scope,
        "total_nodes": len(nodes),
        "changed_nodes": changed_nodes,
        "impacted_edges": impacted_edges,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Extract a minimal Kubernetes topology delta for AI pre-release audit."
    )
    parser.add_argument(
        "--file",
        "-f",
        help="rendered manifest to read (default: stdin)",
    )
    parser.add_argument(
        "--db",
        default=DEFAULT_DB,
        help="SQLite snapshot path (default: %s)" % DEFAULT_DB,
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="emit every node instead of only the delta (first-run / full audit)",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="clear the stored snapshot before comparing",
    )
    parser.add_argument(
        "--no-update",
        action="store_true",
        help="do not write the new state back to the snapshot (dry run)",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indent; use 0 for compact output (default: 2)",
    )
    args = parser.parse_args(argv)

    if args.file:
        with open(args.file, "r", encoding="utf-8") as handle:
            nodes = build_nodes(handle)
    else:
        nodes = build_nodes(sys.stdin)

    conn = open_db(args.db, reset=args.reset)
    try:
        known_hashes = load_hashes(conn)
        first_run = not known_hashes
        delta_ids, impacted_edges = compute_delta(
            nodes, known_hashes, audit_all=args.all or first_run
        )
        if not args.no_update:
            save_nodes(conn, nodes.values())
    finally:
        conn.close()

    if args.all or first_run:
        scope = "full-baseline"
    else:
        scope = "local-delta"
    payload = build_payload(nodes, delta_ids, impacted_edges, scope)

    json.dump(payload, sys.stdout, indent=args.indent or None, sort_keys=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
