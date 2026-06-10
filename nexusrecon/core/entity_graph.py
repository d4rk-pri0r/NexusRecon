"""
NexusRecon Living Intelligence Graph — the central reasoning substrate.

(Previously known as the "Entity Graph"; ``LivingGraph`` is the alias
the METASPLOIT_PLAN document uses for the same class. The
``EntityGraph`` name survives as the canonical export so the rest
of the codebase doesn't churn on a rename; new code is encouraged to
import ``LivingGraph`` to signal architectural intent.)

Backed by NetworkX DiGraph. All entities are nodes, all relationships
are directed edges. The graph is serialized to JSON for state
persistence and to pyvis HTML for reporting.

Entity resolution: when two tools report the same logical entity
(e.g., same domain from WHOIS and from crt.sh), they are merged into
a single node with combined sources and metadata.

What the graph carries after Phase 0.1
- **Infrastructure entities** (the original surface): domains,
  subdomains, IPs, certs, cloud assets, code repositories,
  secrets, technologies, CVEs, URLs.
- **Identity entities** (Phase 0.1 PR B unification): people
  ingested from the Phase D :class:`IdentityGraph`, with their
  identifiers (emails, handles) as their own typed entities +
  HAS_ACCOUNT edges back to the person.
- **Reasoning artifacts** (Phase 0.0): hypotheses, leads,
  open-questions surfaced by the correlation phase, with
  CITES / BLOCKS edges back to the entities they're based on.
- **Human-to-human edges** (Phase 0.1 PR B): Phase E
  RelationshipEdges translated to typed edges
  (COLLABORATES_WITH, FOLLOWS, KNOWS, FEDERATED_WITH) between
  person nodes.

What's still TODO per ARCHITECTURE.md §13-22
- Confidence propagation (Phase 2 verification engine).
- Time-travel / versioning (explicitly deferred — owner
  decision in audit §9.3).
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


#: Relationship types where an entity can have AT MOST ONE
#: outgoing edge — adding a second triggers
#: ``exclusive_rel_conflict`` for the ContradictionDetector.
#: Membership here is conservative: only relationships with
#: clear singular-ownership semantics qualify. ``RESOLVES_TO``
#: is excluded because DNS records routinely have multiple
#: targets; ``HAS_TECH`` is excluded because an entity can use
#: many technologies. Future relationship types added to
#: :class:`~nexusrecon.models.entities.RelationshipType` opt
#: in here when their semantics demand it.
_EXCLUSIVE_REL_TYPES: frozenset[str] = frozenset({
    "belongs_to", "owns", "part_of", "registered_by",
    "hosted_on",
})


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
        # Phase 2 PR A: mutation listeners. Each callable receives
        # one event dict per mutation: ``{"kind": "entity_added" |
        # "entity_merged" | "relationship_added", "entity_id":
        # ..., "entity_type": ..., "rel_type": ..., ...}``.
        # Listener exceptions are swallowed + logged so a broken
        # verifier can't break a campaign.
        self._mutation_listeners: list[Any] = []

    def register_mutation_listener(self, callback: Any) -> None:
        """Register a callable invoked once per add_entity /
        add_relationship call.

        Phase 2 PR A introduces this seam so the verification
        orchestrator can react to graph mutations. Listeners
        are append-only; ``clear_mutation_listeners`` resets the
        list (tests use this to keep the graph singleton
        clean across cases)."""
        self._mutation_listeners.append(callback)

    def clear_mutation_listeners(self) -> None:
        """Remove every registered mutation listener. Mainly for
        tests + tear-down between campaigns."""
        self._mutation_listeners = []

    def set_confidence(
        self,
        entity_id: str,
        new_confidence: float,
        *,
        reason: str = "",
        source: str = "",
    ) -> bool:
        """Phase 2 PR C: single setter for entity confidence.

        Verifiers should call this rather than mutating
        ``self.graph.nodes[entity_id]["confidence"]`` directly,
        so the change emits a discoverable
        ``confidence_changed`` event the
        :class:`ConfidencePropagator` listens for. Returns
        ``True`` when the write happened, ``False`` when the
        entity is unknown or the new value equals the old.

        ``reason`` and ``source`` flow into the event payload
        verbatim so the propagator can attribute the change
        (and to avoid recursive cycles when the propagator
        itself updates confidence — we filter on
        ``source="propagation"``)."""
        node_data = self.graph.nodes.get(entity_id)
        if node_data is None:
            return False
        old = float(node_data.get("confidence", 0.0))
        new = float(new_confidence)
        if new == old:
            return False
        node_data["confidence"] = new
        self._emit_mutation({
            "kind": "confidence_changed",
            "entity_id": entity_id,
            "old_confidence": old,
            "new_confidence": new,
            "delta": new - old,
            "reason": reason,
            "source": source,
        })
        return True

    def _emit_mutation(self, event: dict[str, Any]) -> None:
        """Internal: fire ``event`` to every listener. Defensive
        — any listener exception is logged at debug and
        swallowed; a broken verifier MUST NOT take down the
        campaign that's writing to the graph."""
        for cb in list(self._mutation_listeners):
            try:
                cb(event)
            except Exception as exc:
                log.debug(
                    "Mutation listener raised — swallowing",
                    error=str(exc),
                )

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

            # Phase 2 PR B: detect sticky-field conflicts BEFORE
            # merging — the merge silently drops new values for
            # fields that already have a value, so this is the
            # only chance to record the divergence. Collected
            # here, emitted as separate events after the merge
            # to keep the ordering ``entity_merged`` →
            # ``sticky_field_conflict`` predictable.
            existing_sources_snapshot = list(
                existing_data.get("sources", []),
            )
            existing_confidence_snapshot = float(
                existing_data.get("confidence", 0.0),
            )
            sticky_conflicts: list[dict[str, Any]] = []
            for k, v in entity.model_dump().items():
                if k in ("entity_id", "entity_type", "value",
                         "sources", "tags", "confidence",
                         "first_seen", "last_seen", "provenance"):
                    continue
                if not v:
                    continue
                existing_v = existing_data.get(k)
                if not existing_v:
                    continue
                if isinstance(v, (str, int, float, bool)) and v != existing_v:
                    sticky_conflicts.append({
                        "field": k,
                        "existing_value": existing_v,
                        "incoming_value": v,
                    })

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
            self._emit_mutation({
                "kind": "entity_merged",
                "entity_id": existing_id,
                "entity_type": entity.entity_type.value,
                "value": entity.value,
                "new_sources": list(entity.sources),
            })
            for conflict in sticky_conflicts:
                self._emit_mutation({
                    "kind": "sticky_field_conflict",
                    "entity_id": existing_id,
                    "entity_type": entity.entity_type.value,
                    "value": entity.value,
                    "field": conflict["field"],
                    "existing_value": conflict["existing_value"],
                    "incoming_value": conflict["incoming_value"],
                    "existing_sources": existing_sources_snapshot,
                    "incoming_sources": list(entity.sources),
                    "existing_confidence": existing_confidence_snapshot,
                })
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
        self._emit_mutation({
            "kind": "entity_added",
            "entity_id": entity_id,
            "entity_type": entity.entity_type.value,
            "value": entity.value,
            "sources": list(entity.sources),
        })
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
        # Phase 2 PR B: detect exclusive-relationship conflicts
        # BEFORE adding the new edge. Exclusive rel_types are
        # ones an entity can have at most one outgoing edge of
        # (e.g. ``belongs_to``, ``owns``, ``part_of`` —
        # singular ownership semantics). When a new edge of
        # such a type contradicts an existing one, emit a
        # conflict event the ContradictionDetector listens for.
        # NB ``resolves_to`` is intentionally NOT exclusive —
        # DNS records routinely target multiple IPs.
        conflicts: list[dict[str, Any]] = []
        if rel.rel_type.value in _EXCLUSIVE_REL_TYPES:
            for _, existing_target, edge_data in list(
                self.graph.out_edges(rel.source_id, data=True),
            ):
                if (
                    edge_data.get("rel_type") == rel.rel_type.value
                    and existing_target != rel.target_id
                ):
                    conflicts.append({
                        "existing_target": existing_target,
                        "existing_confidence": float(
                            edge_data.get("confidence", 0.0),
                        ),
                        "existing_source_tool": str(
                            edge_data.get("source_tool", "") or "",
                        ),
                    })

        self.graph.add_edge(rel.source_id, rel.target_id, **data)
        self._emit_mutation({
            "kind": "relationship_added",
            "source_id": rel.source_id,
            "target_id": rel.target_id,
            "rel_type": rel.rel_type.value,
            "confidence": rel.confidence,
        })
        for c in conflicts:
            self._emit_mutation({
                "kind": "exclusive_rel_conflict",
                "source_id": rel.source_id,
                "rel_type": rel.rel_type.value,
                "existing_target": c["existing_target"],
                "existing_confidence": c["existing_confidence"],
                "existing_source_tool": c["existing_source_tool"],
                "incoming_target": rel.target_id,
                "incoming_confidence": rel.confidence,
                "incoming_source_tool": rel.source_tool or "",
            })
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

    # ── Phase 0.1 path-finding API ────────────────────────────────────────────

    def find_paths(
        self,
        source_id: str,
        target_id: str,
        *,
        max_length: int = 5,
        relationship_types: list[RelationshipType] | None = None,
        min_edge_confidence: float = 0.0,
    ) -> list[list[str]]:
        """Find ALL simple paths between two entities, with
        filters.

        The plan calls for ``graph.find_paths(from_entity,
        to_entity, max_length=4, relationship_types=[
        "controls", "owns"])``. This is that surface.

        Args:
            source_id: Starting entity id.
            target_id: Destination entity id.
            max_length: Cap on hops. Longer paths are pruned
                during search so we don't enumerate the entire
                graph for distant pairs.
            relationship_types: When provided, only edges of
                these types contribute to paths. ``None`` (the
                default) accepts every edge type.
            min_edge_confidence: Floor on edge confidence; edges
                below the threshold are skipped. Useful for
                "only show me paths through high-confidence
                relationships".

        Returns:
            List of paths; each path is a list of entity_ids
            in traversal order. Empty list when no qualifying
            paths exist.
        """
        if source_id not in self.graph or target_id not in self.graph:
            return []

        # Build a view of the graph that drops edges failing the
        # filter. NetworkX's ``subgraph_view`` is the canonical
        # way to do this without copying nodes.
        wanted_types: set[str] | None = None
        if relationship_types:
            wanted_types = {rt.value for rt in relationship_types}

        def _edge_ok(u: str, v: str) -> bool:
            data = self.graph.get_edge_data(u, v) or {}
            if wanted_types is not None:
                if data.get("rel_type") not in wanted_types:
                    return False
            if float(data.get("confidence", 1.0) or 0.0) < min_edge_confidence:
                return False
            return True

        view = nx.subgraph_view(self.graph, filter_edge=_edge_ok)
        try:
            return list(
                nx.all_simple_paths(
                    view, source_id, target_id, cutoff=max_length,
                ),
            )
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def get_attack_surface_nodes(
        self,
        *,
        min_confidence: float = 0.6,
        entity_types: list[EntityType] | None = None,
    ) -> list[dict[str, Any]]:
        """Return nodes that are candidates for the attack
        surface ── high-confidence + (optionally) restricted
        to attack-relevant types.

        Default types when none provided: SUBDOMAIN, CLOUD_ASSET,
        REPOSITORY, SECRET, CVE, URL — the entities a red-teamer
        actively pivots into. Identity / Person / Hypothesis
        are intentionally excluded; those are the WHO surface,
        not the WHAT.
        """
        if entity_types is None:
            entity_types = [
                EntityType.SUBDOMAIN,
                EntityType.CLOUD_ASSET,
                EntityType.REPOSITORY,
                EntityType.SECRET,
                EntityType.CVE,
                EntityType.URL,
            ]
        wanted = {t.value for t in entity_types}
        out: list[dict[str, Any]] = []
        for _, data in self.graph.nodes(data=True):
            if data.get("entity_type") not in wanted:
                continue
            if float(data.get("confidence", 1.0) or 0.0) < min_confidence:
                continue
            out.append(dict(data))
        return out

    def get_neighbors_filtered(
        self,
        entity_id: str,
        *,
        edge_type: RelationshipType | None = None,
        direction: str = "both",
    ) -> list[dict[str, Any]]:
        """Phase 0.1 surface from the plan:
        ``graph.get_neighbors(entity_id, edge_type=
        "has_credential", direction="out")``.

        Args:
            entity_id: Source/anchor entity.
            edge_type: When provided, only neighbors reached via
                this edge type are returned.
            direction: ``"out"`` (successors), ``"in"``
                (predecessors), or ``"both"``.
        """
        if entity_id not in self.graph:
            return []
        wanted_type: str | None = edge_type.value if edge_type else None
        out: list[dict[str, Any]] = []
        seen: set[str] = set()

        def _walk(nodes_iter, get_data_for_edge) -> None:
            for n in nodes_iter:
                if n in seen:
                    continue
                if wanted_type:
                    data = get_data_for_edge(n) or {}
                    if data.get("rel_type") != wanted_type:
                        continue
                seen.add(n)
                node_data = self.get_entity(n)
                if node_data:
                    out.append(node_data)

        if direction in ("out", "both"):
            _walk(
                self.graph.successors(entity_id),
                lambda n: self.graph.get_edge_data(entity_id, n),
            )
        if direction in ("in", "both"):
            _walk(
                self.graph.predecessors(entity_id),
                lambda n: self.graph.get_edge_data(n, entity_id),
            )
        return out

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

    # ── Phase 0.1 PR B: three-graph unification ───────────────────────────────

    def merge_identity(self, identity: Any) -> str:
        """Ingest one Phase D :class:`Identity` as a
        :class:`PersonEntity` in this graph + relate the
        person's identifiers as their own nodes.

        Returns the entity_id of the merged PersonEntity. The
        EntityGraph's ``(type, value)`` dedup ensures that
        re-ingesting the same identity is a no-op past the
        first call.

        We use ``identity.identity_id`` as the PersonEntity's
        ``value`` (and entity_id) so the Phase D content-derived
        id round-trips. ``primary_label`` becomes ``full_name``
        on the PersonEntity for operator-readable display in
        reports.
        """
        from nexusrecon.models.entities import (
            EmailEntity, PersonEntity, UsernameEntity,
        )

        # Idempotency: if this identity is already in the graph
        # (re-ingest path), return the existing entity_id.
        existing = self._value_index.get(
            (EntityType.PERSON.value, identity.identity_id.lower()),
        )
        if existing:
            return existing

        # Build the PersonEntity. Use the identity's id as both
        # entity_id (cross-graph stable) and value (dedup key).
        person = PersonEntity(
            entity_id=identity.identity_id,
            value=identity.identity_id,
            full_name=identity.primary_label or identity.identity_id,
            metadata=dict(identity.metadata or {}),
            confidence=max(
                (idr.confidence for idr in (identity.identifiers or [])),
                default=1.0,
            ),
        )
        # Source list: union of identifier sources.
        for idr in identity.identifiers or []:
            if idr.source and idr.source not in person.sources:
                person.sources.append(idr.source)

        person_id = self.add_entity(person)
        # Collect non-typed identifier rows (real_name, phone,
        # domain, other) here; flushed onto the node's
        # metadata at the end so the graph snapshot picks them
        # up.
        extra_identifier_rows: list[dict[str, Any]] = []

        # Each identifier becomes its own typed entity + edge.
        for idr in identity.identifiers or []:
            it_value = idr.identifier_type.value
            if it_value in ("corp_email", "personal_email"):
                # Email entity + HAS_ACCOUNT edge from person → email.
                parts = idr.value.lower().split("@")
                local = parts[0] if len(parts) == 2 else idr.value
                domain = parts[1] if len(parts) == 2 else ""
                em = EmailEntity(
                    value=idr.value.lower(),
                    local_part=local,
                    domain=domain,
                    sources=[idr.source] if idr.source else [],
                    confidence=idr.confidence,
                )
                em_id = self.add_entity(em)
                self.relate(
                    person_id, em_id,
                    RelationshipType.HAS_ACCOUNT,
                    confidence=idr.confidence,
                    source_tool=idr.source or None,
                    evidence=f"identifier_type={it_value}",
                )
            elif it_value == "handle":
                # Username entity + HAS_ACCOUNT edge. The
                # ``service`` field on the identifier carries
                # which platform (GitHub, Mastodon, etc.).
                un = UsernameEntity(
                    value=idr.value,
                    username=idr.value,
                    platforms_found=[idr.service] if idr.service else [],
                    sources=[idr.source] if idr.source else [],
                    confidence=idr.confidence,
                )
                un_id = self.add_entity(un)
                self.relate(
                    person_id, un_id,
                    RelationshipType.HAS_ACCOUNT,
                    confidence=idr.confidence,
                    source_tool=idr.source or None,
                    evidence=f"service={idr.service or '?'}",
                )
            # ``real_name`` / ``phone`` / etc. fold into the
            # PersonEntity's typed fields where applicable. For
            # now we keep them on metadata so the operator can
            # see the raw identifier list without losing
            # nuance.
            else:
                extra_identifier_rows.append({
                    "value": idr.value,
                    "type": it_value,
                    "service": idr.service,
                    "source": idr.source,
                    "confidence": idr.confidence,
                })

        # Credential exposures fold onto the person node as
        # metadata for now. A future Phase 2 verification PR
        # can promote them to standalone Breach entities with
        # edges back; this PR is unification, not surface
        # explosion.
        exposures_meta = []
        for exposure in identity.credential_exposures or []:
            exposures_meta.append({
                "breach_source": exposure.breach_source,
                "breach_date": exposure.breach_date,
                "observed_at_identifier": exposure.observed_at_identifier,
                "credential_kind": exposure.credential_kind,
                "confidence": exposure.confidence.value
                if hasattr(exposure.confidence, "value")
                else str(exposure.confidence),
            })

        # Sync the post-add mutations back onto the graph node.
        # ``add_entity`` already snapshotted the person via
        # ``model_dump()``, so the in-place changes we made
        # above aren't visible in the graph until we mirror
        # them explicitly. Doing it once at the end keeps the
        # node update cheap.
        if extra_identifier_rows or exposures_meta:
            node_metadata = dict(self.graph.nodes[person_id].get("metadata") or {})
            if extra_identifier_rows:
                node_metadata["extra_identifiers"] = extra_identifier_rows
            if exposures_meta:
                node_metadata["credential_exposures"] = exposures_meta
            self.graph.nodes[person_id]["metadata"] = node_metadata

        return person_id

    def merge_identity_graph(self, identity_graph: Any) -> int:
        """Ingest every identity from a Phase D ``IdentityGraph``.

        Iterates :meth:`IdentityGraph.all` and calls
        :meth:`merge_identity` for each. Returns the count of
        identities ingested.
        """
        if identity_graph is None:
            return 0
        count = 0
        for identity in identity_graph.all():
            self.merge_identity(identity)
            count += 1
        return count

    #: Mapping from Phase E ``RelationshipEdge.interaction_type``
    #: strings to the :class:`RelationshipType` enum value the
    #: edge becomes in the unified EntityGraph. Unknown
    #: interaction types fall back to KNOWS so we don't lose
    #: edges to schema drift.
    _INTERACTION_TO_REL_TYPE: dict[str, RelationshipType] = {
        "co_author": RelationshipType.COLLABORATES_WITH,
        "collaborator": RelationshipType.COLLABORATES_WITH,
        "co_committer": RelationshipType.COLLABORATES_WITH,
        "co_speaker": RelationshipType.COLLABORATES_WITH,
        "follower": RelationshipType.FOLLOWS,
        "following": RelationshipType.FOLLOWS,
        "follows": RelationshipType.FOLLOWS,
        "reply": RelationshipType.KNOWS,
        "mention": RelationshipType.KNOWS,
        "boost": RelationshipType.KNOWS,
        "endorses": RelationshipType.KNOWS,
        "federated_with": RelationshipType.FEDERATED_WITH,
    }

    def merge_relationship_graph(self, rel_graph: Any) -> int:
        """Ingest every edge from a Phase E :class:`RelationshipGraph`
        as a typed :class:`EntityRelationship` between the two
        person nodes.

        Assumes the corresponding identities have already been
        merged (via :meth:`merge_identity_graph` or
        :meth:`merge_identity`) so the source/target person
        nodes exist. Edges between missing nodes are silently
        skipped — same tolerance the audit logs require.

        Returns the count of edges ingested.
        """
        if rel_graph is None:
            return 0
        count = 0
        # The RelationshipGraph exposes its edges via ``all_edges()``
        # returning ``(source_id, edge)`` tuples; fall back to a
        # private accessor for graphs that pre-date that API.
        if hasattr(rel_graph, "all_edges"):
            iter_edges = rel_graph.all_edges()
        else:
            iter_edges = []
            for src, idx_list in getattr(rel_graph, "_by_source", {}).items():
                for idx in idx_list:
                    iter_edges.append((src, rel_graph._edges[idx]))

        for source_id, edge in iter_edges:
            target_id = edge.target_identity_id
            # Confirm both person nodes are in the graph.
            if source_id not in self.graph or target_id not in self.graph:
                continue
            rel_type = self._INTERACTION_TO_REL_TYPE.get(
                edge.interaction_type, RelationshipType.KNOWS,
            )
            self.relate(
                source_id, target_id, rel_type,
                confidence=float(edge.strength or 1.0),
                evidence=f"interaction_type={edge.interaction_type}; "
                         f"last_observed={edge.last_observed}",
                source_tool=(edge.sources[0] if edge.sources else None),
            )
            count += 1
        return count

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
        # Id maps so later passes can draw real edges between entities (the
        # graph was previously an edge-poor dedup bag; these let us connect
        # subdomains to their domain, to their resolved IPs and technologies,
        # and repos to their leaked secrets).
        sub_to_id: dict[str, str] = {}
        domain_to_id: dict[str, str] = {}
        repo_to_id: dict[str, str] = {}

        def _ensure_domain(d: str, source: str) -> str | None:
            if not isinstance(d, str) or not d:
                return None
            did = domain_to_id.get(d)
            if did is None:
                did = g.add_domain(d, source=source)
                domain_to_id[d] = did
            return did

        # Seed domains as first-class DOMAIN nodes (the graph backbone).
        for seed in (state.get("seeds") or []):
            _ensure_domain(seed, "scope")

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
            sid = g.add_subdomain(sub, parent=parent, source=source)
            sub_to_id[sub] = sid
            # Connect the subdomain to its parent domain node so the graph is
            # traversable from the seed down rather than a flat list.
            did = _ensure_domain(parent, source)
            if did is not None and did != sid:
                g.relate(did, sid, RelationshipType.HAS_SUBDOMAIN, source_tool=source)

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
            repo_to_id[key] = g.add_repository(
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

        # IPs + technologies from active-probe output (httpx writes
        # ``infra_intel[sub] = {"results": [<httpx json>...]}`` where each row
        # carries ``a`` (resolved A records) and ``tech``). Each becomes a typed
        # node with a RESOLVES_TO / HAS_TECH edge from the subdomain. Wrapped so
        # a shape surprise from a tool-version bump never breaks the rebuild.
        import ipaddress

        def _is_ip(val: Any) -> bool:
            try:
                ipaddress.ip_address(str(val))
                return True
            except Exception:
                return False

        infra_intel = state.get("infra_intel") or {}
        for sub, sid in sub_to_id.items():
            info = infra_intel.get(sub)
            if not isinstance(info, dict):
                continue
            results = info.get("results")
            rows = results if isinstance(results, list) else [info]
            for row in rows:
                if not isinstance(row, dict):
                    continue
                try:
                    ip_candidates: list[str] = []
                    a_records = row.get("a")
                    if isinstance(a_records, list):
                        ip_candidates.extend(str(x) for x in a_records)
                    for k in ("ip", "host"):
                        v = row.get(k)
                        if isinstance(v, str):
                            ip_candidates.append(v)
                    for ip in ip_candidates:
                        if _is_ip(ip):
                            ip_id = g.add_ip(ip, source="phase5")
                            g.relate(sid, ip_id, RelationshipType.RESOLVES_TO,
                                     source_tool="phase5")
                    techs = row.get("tech") or row.get("technologies") or []
                    if isinstance(techs, list):
                        for tech in techs:
                            if isinstance(tech, str) and tech.strip():
                                tech_id = g.add_technology(tech.strip(), source="phase5")
                                g.relate(sid, tech_id, RelationshipType.HAS_TECH,
                                         source_tool="phase5")
                except Exception:
                    continue

        # Secrets from code leakage (gitleaks ``leaks`` / trufflehog +
        # github_recon ``findings``). We store a NON-SENSITIVE label (rule +
        # file), never the raw secret value, and link it to its repository.
        for key, data in code_intel.items():
            if not isinstance(data, dict):
                continue
            repo_id = repo_to_id.get(key)
            if repo_id is None:
                continue
            secret_items = data.get("leaks") or data.get("findings") or []
            if not isinstance(secret_items, list):
                continue
            for i, item in enumerate(secret_items):
                if not isinstance(item, dict):
                    continue
                try:
                    rule = (
                        item.get("RuleID") or item.get("DetectorName")
                        or item.get("rule") or item.get("type") or "secret"
                    )
                    loc = item.get("File") or item.get("file") or item.get("path") or ""
                    label = f"{rule}@{loc}" if loc else f"{key}:{rule}#{i}"
                    secret_id = g.add_secret(label, secret_type=str(rule), source="phase3")
                    g.relate(repo_id, secret_id, RelationshipType.CONTAINS_SECRET,
                             source_tool="phase3")
                except Exception:
                    continue

        # Reasoning artifacts → first-class nodes WITH edges back to evidence.
        # Each hypothesis / lead CITES every entity whose value is mentioned in
        # its statement (mention-based linkage, evidence-labelled), and each
        # open question BLOCKS any lead / hypothesis that shares a cited entity.
        # This is the "explain a finding as a graph traversal" capability: the
        # reasoning layer is no longer a set of disconnected text nodes.
        _CITABLE_TYPES = {
            "domain", "subdomain", "email", "ip_address", "cve",
            "cloud_asset", "technology", "repository", "person", "username",
        }
        citable: list[tuple[str, str]] = []
        for nid, ndata in g.graph.nodes(data=True):
            if ndata.get("entity_type") in _CITABLE_TYPES:
                val = str(ndata.get("value") or "")
                if len(val) >= 4:  # skip trivially short values to avoid noise
                    citable.append((val.lower(), nid))

        def _mentioned_ids(text: str) -> list[str]:
            t = (text or "").lower()
            return [nid for val, nid in citable if val in t]

        downstream: list[tuple[str, set[str]]] = []  # (node_id, cited entity ids)
        for h in (state.get("hypotheses") or []):
            if isinstance(h, str) and h:
                cites = _mentioned_ids(h)
                hid = g.add_hypothesis(h, source="phase4_correlation",
                                       generated_by="phase4", cites=cites)
                downstream.append((hid, set(cites)))
        for ld in (state.get("confirmed_leads") or []):
            if isinstance(ld, str) and ld:
                cites = _mentioned_ids(ld)
                lid = g.add_lead(ld, source="phase4_correlation", cites=cites)
                downstream.append((lid, set(cites)))
        for q in (state.get("open_questions") or []):
            if isinstance(q, str) and q:
                q_ents = set(_mentioned_ids(q))
                blocks = [
                    nid for nid, ents in downstream if q_ents and (ents & q_ents)
                ]
                g.add_open_question(q, source="phase4_correlation", blocks=blocks)

        # Phase 0.1 PR B: pull the Phase D IdentityGraph + Phase E
        # RelationshipGraph into the unified EntityGraph when
        # present in state. Each Identity becomes a PersonEntity;
        # each Identifier becomes its typed entity + HAS_ACCOUNT
        # edge; each RelationshipEdge becomes a typed KNOWS /
        # COLLABORATES_WITH / FOLLOWS / FEDERATED_WITH edge
        # between the corresponding person nodes. Missing graphs
        # are tolerated — older state.json files lack these
        # entirely.
        identity_graph_dict = state.get("identity_graph") or {}
        if isinstance(identity_graph_dict, dict) and identity_graph_dict.get("identities"):
            try:
                from nexusrecon.core.identity_graph import IdentityGraph
                idg = IdentityGraph.from_dict(identity_graph_dict)
                g.merge_identity_graph(idg)
            except Exception:
                # Identity graph deserialization is best-effort
                # — schema drift between releases shouldn't
                # break phase4 / phase8.
                pass

        relationship_graph_dict = state.get("relationship_graph") or {}
        if isinstance(relationship_graph_dict, dict) and relationship_graph_dict.get("edges"):
            try:
                from nexusrecon.core.relationship_graph import RelationshipGraph
                rg = RelationshipGraph.from_dict(relationship_graph_dict)
                g.merge_relationship_graph(rg)
            except Exception:
                pass

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


# ──────────────────────────────────────────────────────────────────────
# Public alias for the METASPLOIT_PLAN's preferred name
# ──────────────────────────────────────────────────────────────────────

#: Architectural alias matching the language used in
#: ARCHITECTURE.md §13-22. New code should
#: import :class:`LivingGraph` to signal "this is the central
#: reasoning substrate, not just an entity store." The
#: ``EntityGraph`` name survives as the canonical class so the
#: existing codebase doesn't churn on a rename.
#:
#: Migration path: when a forcing function appears (e.g. an
#: API-breaking refactor of the class itself), rename the
#: class in-place and the alias here flips so ``EntityGraph``
#: becomes the deprecated name.
LivingGraph = EntityGraph

#: Schema version of the serialised graph dict. Bumps every
#: time ``EntityGraph.to_dict`` adds a new top-level key or
#: changes the shape of an existing one. The migration script
#: at ``scripts/migrate_state_to_living_graph.py`` reads this
#: to decide whether an on-disk graph dict needs upgrading.
GRAPH_SCHEMA_VERSION: str = "0.1"

__all__ = [
    "EntityGraph",
    "LivingGraph",
    "GRAPH_SCHEMA_VERSION",
]
