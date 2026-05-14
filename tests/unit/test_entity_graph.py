"""Tests for core/entity_graph.py."""
import pytest
from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.models.entities import EntityType, RelationshipType


@pytest.fixture
def graph():
    return EntityGraph(campaign_id="test-1", engagement_id="E-01")


class TestEntityGraph:
    def test_add_domain(self, graph):
        eid = graph.add_domain("acme.com", source="whois")
        assert eid is not None
        entity = graph.get_entity(eid)
        assert entity["value"] == "acme.com"

    def test_dedup_same_domain(self, graph):
        id1 = graph.add_domain("acme.com", source="whois")
        id2 = graph.add_domain("acme.com", source="crtsh")
        assert id1 == id2  # same entity, merged

    def test_add_subdomain(self, graph):
        eid = graph.add_subdomain("dev.acme.com", "acme.com", source="subfinder")
        entity = graph.get_entity(eid)
        assert entity["value"] == "dev.acme.com"
        assert entity["parent_domain"] == "acme.com"

    def test_relationship(self, graph):
        d_id = graph.add_domain("acme.com", source="whois")
        s_id = graph.add_subdomain("dev.acme.com", "acme.com", source="subfinder")
        graph.relate(d_id, s_id, RelationshipType.HAS_SUBDOMAIN, source_tool="subfinder")
        assert graph.graph.number_of_edges() == 1

    def test_stats(self, graph):
        graph.add_domain("acme.com", source="whois")
        graph.add_subdomain("dev.acme.com", "acme.com", source="subfinder")
        graph.add_email("admin@acme.com", source="hunter")
        stats = graph.stats()
        assert stats["total_entities"] == 3
        assert stats["by_type"]["domain"] == 1
        assert stats["by_type"]["subdomain"] == 1
        assert stats["by_type"]["email"] == 1

    def test_serialize_roundtrip(self, graph):
        graph.add_domain("acme.com", source="whois")
        graph.add_ip("1.2.3.4", source="shodan")
        data = graph.to_dict()
        g2 = EntityGraph.from_dict(data)
        assert g2.graph.number_of_nodes() == 2

    def test_get_entities_by_type(self, graph):
        graph.add_domain("acme.com", source="whois")
        graph.add_subdomain("dev.acme.com", "acme.com", source="crtsh")
        graph.add_subdomain("mail.acme.com", "acme.com", source="subfinder")
        subs = graph.get_entities_by_type(EntityType.SUBDOMAIN)
        assert len(subs) == 2
