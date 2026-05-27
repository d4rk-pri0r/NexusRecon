"""
NexusRecon entity graph — the central intelligence accumulator.

Backed by NetworkX DiGraph.  All entities are nodes, all relationships
are directed edges.  The graph is serialized to JSON for state persistence
and to pyvis HTML for reporting.

Entity resolution: when two tools report the same logical entity
(e.g., same domain from WHOIS and from crt.sh), they are merged into
a single node with combined sources and metadata.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

import networkx as nx
import structlog

from nexusrecon.models.entities import (
    BaseEntity,
    CloudAssetEntity,
    CVEEntity,
    DomainEntity,
    EmailEntity,
    EntityRelationship,
    EntityType,
    HypothesisEntity,
    IPAddressEntity,
    LeadEntity,
    OpenQuestionEntity,
    PersonEntity,
    RelationshipType,
    RepositoryEntity,
    SecretEntity,
    SubdomainEntity,
    TechnologyEntity,
)

log = structlog.get_logger(__name__)
E = TypeVar("E", bound=BaseEntity)


class EntityGraph:
    """
    Directed entity graph with deduplication and provenance tracking.

    Nodes: entities (domain, IP, email, person, cloud asset, etc.)
    Edges: relationships (resolves_to, has_subdomain, contains_secret, etc.)
    """

    def __init__(self, campaign_id: str, engagement_id: str) -> None:
        self.campaign_id = campaign_id
        self.engagement_id = engagement_id
        self.graph = nx.DiGraph()
        self._value_index: dict[tuple[str, str], str] = {}  # (type, value) -> entity_id

    # ── Entity management ─────────────────────────────────────────────────────

    def add_entity(self, entity: BaseEntity) -> str:
        """
        Add entity to graph.  If an entity with the same (type, value)
        already exists, merge the new entity's sources and metadata
        into the existing one and return the existing entity_id.
        """
        entity.engagement_id = self.engagement_id
        idx_key = (entity.entity_type.value, entity.value.lower())

        if idx_key in self._value_index:
            # Merge into existing
            existing_id = self._value_index[idx_key]
            existing_data = self.graph.nodes[existing_id]
            # Merge sources
            existing_sources = set(existing_data.get("sources", []))
            existing_sources.update(entity.sources)
            existing_data["sources"] = list(existing_sources)
            # Merge tags
            existing_tags = set(existing_data.get("tags", []))
            existing_tags.update(entity.tags)
            existing_data["tags"] = list(existing_tags)
            # Update confidence (take max)
            existing_data["confidence"] = max(
                existing_data.get("confidence", 0.0), entity.confidence
            )
            # Update last_seen
            existing_data["last_seen"] = datetime.utcnow().isoformat()
            # Merge extra metadata fields
            for k, v in entity.model_dump().items():
                if k not in ("entity_id", "entity_type", "value", "sources",
                             "tags", "confidence", "first_seen", "last_seen"):
                    if v and not existing_data.get(k):
                        existing_data[k] = v
            log.debug("Merged entity", entity_type=entity.entity_type, value=entity.value)
            return existing_id

        # New entity
        entity_id = entity.entity_id
        data = entity.model_dump()
        # Serialize datetimes
        for k, v in data.items():
            if isinstance(v, datetime):
                data[k] = v.isoformat()
        self.graph.add_node(entity_id, **data)
        self._value_index[idx_key] = entity_id
        log.debug("Added entity", entity_type=entity.entity_type.value, value=entity.value)
        return entity_id

    def get_entity_id(self, entity_type: EntityType, value: str) -> str | None:
        """Return entity_id for a known (type, value) pair, or None."""
        return self._value_index.get((entity_type.value, value.lower()))

    def get_entity(self, entity_id: str) -> dict[str, Any] | None:
        """Return entity node data dict, or None."""
        if entity_id in self.graph:
            return dict(self.graph.nodes[entity_id])
        return None

    def get_entities_by_type(self, entity_type: EntityType) -> list[dict[str, Any]]:
        """Return all entities of a given type."""
        return [
            dict(data)
            for _, data in self.graph.nodes(data=True)
            if data.get("entity_type") == entity_type.value
        ]

    def remove_entity(self, entity_id: str) -> None:
        if entity_id in self.graph:
            self.graph.remove_node(entity_id)
            # Remove from index
            self._value_index = {
                k: v for k, v in self._value_index.items() if v != entity_id
            }

    # ── Relationship management ───────────────────────────────────────────────

    def add_relationship(self, rel: EntityRelationship) -> str:
        """Add a directed relationship edge."""
        if rel.source_id not in self.graph:
            log.warning("Relationship source not in graph", source_id=rel.source_id)
            return rel.rel_id
        if rel.target_id not in self.graph:
            log.warning("Relationship target not in graph", target_id=rel.target_id)
            return rel.rel_id

        data = {
            "rel_id": rel.rel_id,
            "rel_type": rel.rel_type.value,
            "confidence": rel.confidence,
            "evidence": rel.evidence,
            "source_tool": rel.source_tool,
            "timestamp": rel.timestamp.isoformat(),
            **rel.metadata,
        }
        self.graph.add_edge(rel.source_id, rel.target_id, **data)
        return rel.rel_id

    def relate(
        self,
        source_id: str,
        target_id: str,
        rel_type: RelationshipType,
        *,
        confidence: float = 1.0,
        evidence: str | None = None,
        source_tool: str | None = None,
    ) -> None:
        """Convenience method to add a relationship."""
        rel = EntityRelationship(
            source_id=source_id,
            target_id=target_id,
            rel_type=rel_type,
            confidence=confidence,
            evidence=evidence,
            source_tool=source_tool,
        )
        self.add_relationship(rel)

    # ── Convenience entity builders ───────────────────────────────────────────

    def add_domain(self, domain: str, source: str, **kwargs: Any) -> str:
        e = DomainEntity(value=domain, sources=[source], **kwargs)
        return self.add_entity(e)

    def add_subdomain(self, subdomain: str, parent: str, source: str, **kwargs: Any) -> str:
        e = SubdomainEntity(value=subdomain, parent_domain=parent, sources=[source], **kwargs)
        return self.add_entity(e)

    def add_ip(self, ip: str, source: str, **kwargs: Any) -> str:
        e = IPAddressEntity(value=ip, sources=[source], **kwargs)
        return self.add_entity(e)

    def add_email(self, email: str, source: str, **kwargs: Any) -> str:
        parts = email.lower().split("@")
        local = parts[0] if len(parts) == 2 else email
        domain = parts[1] if len(parts) == 2 else ""
        e = EmailEntity(value=email.lower(), local_part=local, domain=domain, sources=[source], **kwargs)
        return self.add_entity(e)

    def add_cloud_asset(self, asset_value: str, provider: str, service: str, source: str, **kwargs: Any) -> str:
        e = CloudAssetEntity(
            value=asset_value, provider=provider, service_type=service,
            sources=[source], **kwargs
        )
        return self.add_entity(e)

    def add_repository(self, full_name: str, platform: str, source: str, **kwargs: Any) -> str:
        parts = full_name.split("/")
        org = parts[0] if len(parts) == 2 else None
        repo_name = parts[-1]
        e = RepositoryEntity(
            value=full_name, platform=platform, full_name=full_name,
            org=org, repo_name=repo_name, sources=[source], **kwargs
        )
        return self.add_entity(e)

    def add_secret(self, identifier: str, secret_type: str, source: str, **kwargs: Any) -> str:
        e = SecretEntity(value=identifier, secret_type=secret_type, sources=[source], **kwargs)
        return self.add_entity(e)

    def add_technology(self, product: str, source: str, **kwargs: Any) -> str:
        e = TechnologyEntity(value=product, product=product, sources=[source], **kwargs)
        return self.add_entity(e)

    def add_cve(self, cve_id: str, source: str, **kwargs: Any) -> str:
        e = CVEEntity(value=cve_id, cve_id=cve_id, sources=[source], **kwargs)
        return self.add_entity(e)

    def add_person(self, name: str, source: str, **kwargs: Any) -> str:
        e = PersonEntity(value=name, full_name=name, sources=[source], **kwargs)
        return self.add_entity(e)

    # ── Reasoning artifacts (Step 0.0) ────────────────────────────────────────

    def add_hypothesis(
        self,
        statement: str,
        source: str,
        *,
        cites: list[str] | None = None,
        confidence: float = 0.6,
        generated_by: str | None = None,
    ) -> str:
        """Add a HypothesisEntity + draw CITES edges to the cited
        entities.

        ``cites`` is the list of entity_ids the hypothesis is
        based on. Missing ids are silently skipped (a
        hypothesis can cite an entity that hasn't landed in the
        graph yet — the edge is added lazily next time)."""
        e = HypothesisEntity(
            value=statement,
            statement=statement,
            cites=list(cites or []),
            confidence=confidence,
            sources=[source],
            generated_by=generated_by,
        )
        hid = self.add_entity(e)
        for cited_id in cites or []:
            if cited_id in self.graph:
                self.relate(hid, cited_id, RelationshipType.CITES,
                            confidence=confidence, source_tool=source)
        return hid

    def add_lead(
        self,
        statement: str,
        source: str,
        *,
        cites: list[str] | None = None,
        confidence: float = 0.8,
        severity: str = "medium",
        recommended_action: str | None = None,
    ) -> str:
        """Add a LeadEntity + draw CITES edges to its evidence."""
        e = LeadEntity(
            value=statement,
            statement=statement,
            cites=list(cites or []),
            confidence=confidence,
            severity=severity,
            recommended_action=recommended_action,
            sources=[source],
        )
        lid = self.add_entity(e)
        for cited_id in cites or []:
            if cited_id in self.graph:
                self.relate(lid, cited_id, RelationshipType.CITES,
                            confidence=confidence, source_tool=source)
        return lid

    def add_open_question(
        self,
        question: str,
        source: str,
        *,
        blocks: list[str] | None = None,
        confidence: float = 0.5,
        suggested_tools: list[str] | None = None,
    ) -> str:
        """Add an OpenQuestionEntity + draw BLOCKS edges to the
        downstream leads/hypotheses it gates."""
        e = OpenQuestionEntity(
            value=question,
            question=question,
            blocks=list(blocks or []),
            suggested_tools=list(suggested_tools or []),
            confidence=confidence,
            sources=[source],
        )
        qid = self.add_entity(e)
        for blocked_id in blocks or []:
            if blocked_id in self.graph:
                self.relate(qid, blocked_id, RelationshipType.BLOCKS,
                            confidence=confidence, source_tool=source)
        return qid

    # ── Statistics ────────────────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        """Return graph statistics."""
        type_counts: dict[str, int] = {}
        for _, data in self.graph.nodes(data=True):
            t = data.get("entity_type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "total_entities": self.graph.number_of_nodes(),
            "total_relationships": self.graph.number_of_edges(),
            "by_type": type_counts,
            "campaign_id": self.campaign_id,
        }

    def get_neighbors(self, entity_id: str) -> list[dict[str, Any]]:
        """Return all entities directly connected to entity_id."""
        result = []
        for neighbor_id in nx.all_neighbors(self.graph, entity_id):
            data = self.get_entity(neighbor_id)
            if data:
                result.append(data)
        return result

    def find_path(self, source_value: str, target_value: str,
                  source_type: EntityType, target_type: EntityType) -> list[str] | None:
        """Find shortest path between two entities by value."""
        sid = self.get_entity_id(source_type, source_value)
        tid = self.get_entity_id(target_type, target_value)
        if not sid or not tid:
            return None
        try:
            return nx.shortest_path(self.graph, sid, tid)
        except nx.NetworkXNoPath:
            return None

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph to a dict suitable for JSON storage."""
        return {
            "campaign_id": self.campaign_id,
            "engagement_id": self.engagement_id,
            "nodes": [
                {"id": nid, **data}
                for nid, data in self.graph.nodes(data=True)
            ],
            "edges": [
                {"source": s, "target": t, **data}
                for s, t, data in self.graph.edges(data=True)
            ],
            "stats": self.stats(),
        }

    def to_json(self, path: str | Path | None = None) -> str:
        """Serialize to JSON string (and optionally write to file)."""
        data = json.dumps(self.to_dict(), default=str, indent=2)
        if path:
            Path(path).write_text(data, encoding="utf-8")
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EntityGraph:
        """Restore from serialized dict."""
        g = cls(data.get("campaign_id", ""), data.get("engagement_id", ""))
        for node in data.get("nodes", []):
            nid = node.pop("id")
            g.graph.add_node(nid, **node)
        for edge in data.get("edges", []):
            s = edge.pop("source")
            t = edge.pop("target")
            g.graph.add_edge(s, t, **edge)
        # Rebuild value index
        for nid, data in g.graph.nodes(data=True):
            etype = data.get("entity_type", "")
            val = data.get("value", "")
            if etype and val:
                g._value_index[(etype, val.lower())] = nid
        return g

    def export_pyvis_html(self, output_path: str | Path) -> str:
        """Export interactive HTML visualization using pyvis."""
        try:
            from pyvis.network import Network
        except ImportError:
            log.warning("pyvis not installed, skipping HTML graph export")
            return ""

        net = Network(
            height="900px", width="100%",
            bgcolor="#1a1a2e", font_color="white",
            directed=True,
        )
        net.toggle_physics(True)

        # Color map by entity type
        type_colors = {
            "domain": "#00d4ff",
            "subdomain": "#00a3cc",
            "ip_address": "#ff6b6b",
            "email": "#ffd93d",
            "person": "#6bcb77",
            "cloud_asset": "#ff922b",
            "repository": "#cc5de8",
            "secret": "#f03e3e",
            "technology": "#74c0fc",
            "cve": "#fa5252",
            "certificate": "#a9e34b",
            "asn": "#f9c74f",
            "social_account": "#90be6d",
            "username": "#4ecdc4",
            "organization": "#45b7d1",
        }

        for nid, data in self.graph.nodes(data=True):
            etype = data.get("entity_type", "unknown")
            val = data.get("value", nid[:8])
            color = type_colors.get(etype, "#888888")
            tooltip = f"Type: {etype}\nValue: {val}\nSources: {', '.join(data.get('sources', []))}"
            net.add_node(nid, label=val[:30], color=color, title=tooltip, shape="dot", size=15)

        for s, t, data in self.graph.edges(data=True):
            rel_type = data.get("rel_type", "")
            net.add_edge(s, t, label=rel_type, color="#888888")

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        net.save_graph(str(output_path))
        return str(output_path)

    @classmethod
    def from_state(
        cls,
        state: dict[str, Any],
        *,
        campaign_id: str = "",
        engagement_id: str = "",
    ) -> EntityGraph:
        """Build a populated :class:`EntityGraph` from the flat
        ``CampaignGraphState`` buckets.

        This is the Step 0.0 bridge: the existing phase
        functions populate ``subdomain_intel`` / ``email_intel``
        / ``cloud_intel`` / ``code_intel`` as dicts; this
        helper materialises them as a real graph the
        correlation + risk-analyst agents can reason over.

        The helper is idempotent under deduplication — calling
        it twice on the same state produces the same graph
        (entities merge by ``(type, value)``). Safe to call
        every phase if cheap.

        Args:
            state: The LangGraph campaign state dict.
            campaign_id: Override; otherwise read from state.
            engagement_id: Override; otherwise read from state.

        Returns:
            A fresh ``EntityGraph`` populated from the flat
            buckets in ``state``. Reasoning artifacts
            (``hypotheses``, ``confirmed_leads``,
            ``open_questions``) are translated to first-class
            HYPOTHESIS / LEAD / OPEN_QUESTION nodes.
        """
        g = cls(
            campaign_id=campaign_id or state.get("campaign_id", ""),
            engagement_id=engagement_id or state.get("engagement_id", ""),
        )
        # Subdomains: each key in subdomain_intel is a subdomain;
        # the values may carry source-tool info. We harvest the
        # source list if present, defaulting to a generic marker.
        subdomain_intel = state.get("subdomain_intel") or {}
        for sub, info in subdomain_intel.items():
            if not isinstance(sub, str) or not sub:
                continue
            sources_field = (
                info.get("sources") if isinstance(info, dict) else None
            )
            source = (
                sources_field[0]
                if isinstance(sources_field, list) and sources_field
                else "phase1"
            )
            # Best-effort parent domain inference: last two labels.
            parts = sub.split(".")
            parent = ".".join(parts[-2:]) if len(parts) >= 2 else sub
            g.add_subdomain(sub, parent=parent, source=source)

        # Emails: email_intel.emails is a dict keyed by address.
        email_intel = state.get("email_intel") or {}
        emails = email_intel.get("emails", {}) if isinstance(email_intel, dict) else {}
        for em, info in emails.items():
            if not isinstance(em, str) or "@" not in em:
                continue
            sources_field = (
                info.get("sources") if isinstance(info, dict) else None
            )
            source = (
                sources_field[0]
                if isinstance(sources_field, list) and sources_field
                else "phase2"
            )
            g.add_email(em, source=source)

        # Cloud assets: cloud_intel keys are typically
        # ``provider/service`` strings; we record one
        # CloudAssetEntity per top-level key. Granular bucket
        # / tenant breakdowns are left for the Phase D / E
        # identity-graph path which already covers them.
        cloud_intel = state.get("cloud_intel") or {}
        for key, data in cloud_intel.items():
            if not isinstance(key, str):
                continue
            provider, _, service = key.partition("/")
            attr_conf = 1.0
            if isinstance(data, dict):
                attr_conf = float(
                    data.get("attribution_confidence", 1.0) or 1.0,
                )
            g.add_cloud_asset(
                key, provider=provider or "unknown",
                service=service or "unknown",
                source="phase2",
                confidence=attr_conf,
            )

        # Code intel: each key is typically a repo / org slug.
        code_intel = state.get("code_intel") or {}
        for key in code_intel:
            if not isinstance(key, str) or not key:
                continue
            # Generic placeholder — code tools store richer info
            # under the key but the graph only needs the slug
            # for cross-referencing in this Step 0.0 wire-up.
            g.add_repository(
                key, platform="github", source="phase3",
            )

        # CVEs from vuln_intel.enriched_cves (Phase D wiring).
        vuln_intel = state.get("vuln_intel") or {}
        enriched = (
            vuln_intel.get("enriched_cves", {})
            if isinstance(vuln_intel, dict) else {}
        )
        for cve_id in enriched:
            if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
                g.add_cve(cve_id, source="phase6")

        # Reasoning artifacts → first-class nodes. The cite/
        # block edges are NOT inferred here (we don't know which
        # entities each hypothesis was based on without re-
        # running the correlation logic). The correlation phase
        # itself is the right place to draw the edges.
        for h in (state.get("hypotheses") or []):
            if isinstance(h, str) and h:
                g.add_hypothesis(h, source="phase4_correlation",
                                 generated_by="phase4")
        for ld in (state.get("confirmed_leads") or []):
            if isinstance(ld, str) and ld:
                g.add_lead(ld, source="phase4_correlation")
        for q in (state.get("open_questions") or []):
            if isinstance(q, str) and q:
                g.add_open_question(q, source="phase4_correlation")

        return g

    def export_maltego_csv(self, output_path: str | Path) -> str:
        """Export entities in Maltego-compatible CSV format."""
        import csv
        output_path = Path(output_path)
        rows = []
        for nid, data in self.graph.nodes(data=True):
            rows.append({
                "Entity Type": data.get("entity_type", ""),
                "Value": data.get("value", ""),
                "Sources": "|".join(data.get("sources", [])),
                "Confidence": data.get("confidence", ""),
                "Tags": "|".join(data.get("tags", [])),
                "First Seen": data.get("first_seen", ""),
                "Last Seen": data.get("last_seen", ""),
            })

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            if rows:
                writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)

        return str(output_path)
