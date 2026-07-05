"""
Neo4j-backed CTI Knowledge Graph — CyberKG
=============================================
RO2: Hybrid KG+vector retrieval for temporal currency of CTI outputs.

Node types: ThreatActor, Campaign, Technique, Malware, Vulnerability,
            IOC, Tool, DataSource
Relationships: USES, TARGETS, EXPLOITS, DELIVERS, ATTRIBUTED_TO,
               PART_OF, MITIGATED_BY

Falls back to NetworkX in-memory graph when Neo4j is unavailable.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# Neo4j connection defaults (match docker-compose.yml)
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASSWORD", "ctishield2026")

# ── Node label constants ─────────────────────────────────────────────
LABELS = {
    "threat_actor": "ThreatActor",
    "campaign": "Campaign",
    "technique": "Technique",
    "malware": "Malware",
    "vulnerability": "Vulnerability",
    "ioc": "IOC",
    "tool": "Tool",
    "data_source": "DataSource",
}

# ── Relationship constants ───────────────────────────────────────────
VALID_RELS = {
    "uses", "targets", "exploits", "delivers", "attributed_to",
    "part_of", "mitigated_by", "related_to", "employs",
    "connects_to", "exfiltrates", "persists_via", "associated_with",
    "operates_from", "controls", "enables",
}

# ── Cypher templates ─────────────────────────────────────────────────

CYPHER_INIT_CONSTRAINTS = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (a:ThreatActor) REQUIRE a.name IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (n:Technique) ON (n.name)",
    "CREATE INDEX IF NOT EXISTS FOR (n:IOC) ON (n.value)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Malware) ON (n.name)",
]

CYPHER_ADD_TRIPLE = """
MERGE (s {name: $subject})
SET s:CTINode, s.updated_at = datetime()
MERGE (o {name: $object})
SET o:CTINode, o.updated_at = datetime()
MERGE (s)-[r:RELATED_TO]->(o)
SET r.type = $predicate,
    r.technique_id = $technique_id,
    r.technique_name = $technique_name,
    r.confidence = $confidence,
    r.source = $source,
    r.first_seen = COALESCE(r.first_seen, datetime()),
    r.last_seen = datetime(),
    r.triple_id = $triple_id
RETURN id(r) AS rid
"""

CYPHER_QUERY_RELATED = """
MATCH (start {name: $entity})
CALL apoc.path.subgraphNodes(start, {maxLevel: $hops}) YIELD node
WITH start, node WHERE node <> start
MATCH (node)-[r]-(neighbor)
RETURN DISTINCT
  node.name AS entity,
  type(r) AS relationship,
  neighbor.name AS related,
  r.technique_id AS technique_id,
  r.confidence AS confidence,
  r.source AS source
LIMIT 50
"""

CYPHER_QUERY_RELATED_SIMPLE = """
MATCH (start {name: $entity})-[r*1..$hops]-(related)
RETURN DISTINCT
  related.name AS entity,
  related.technique_id AS technique_id,
  related.cve_id AS cve_id,
  labels(related) AS labels
LIMIT 50
"""

CYPHER_TTPS_BY_ACTOR = """
MATCH (a:ThreatActor {name: $actor})-[:USES|EMPLOYS*1..2]->(t:Technique)
RETURN DISTINCT t.technique_id AS tid, t.name AS name,
       t.tactic AS tactic, t.source_url AS url
ORDER BY t.technique_id
"""

CYPHER_RECENT_CVES = """
MATCH (v:Vulnerability)
WHERE v.last_seen >= datetime() - duration({days: $days})
OPTIONAL MATCH (v)<-[:EXPLOITS]-(actor)
RETURN v.cve_id AS cve, v.name AS name, v.last_seen AS last_seen,
       COLLECT(DISTINCT actor.name) AS exploited_by
ORDER BY v.last_seen DESC
LIMIT 50
"""

CYPHER_ATTACK_PATH = """
MATCH path = shortestPath(
  (init:Technique {tactic: 'Initial Access'})-[*..6]-(exfil:Technique {tactic: 'Exfiltration'})
)
WHERE init.technique_id = $start_tid OR $start_tid = ''
RETURN [n IN nodes(path) | n.name] AS chain,
       [r IN relationships(path) | type(r)] AS rels,
       length(path) AS hops
LIMIT 5
"""

CYPHER_SEARCH_TECHNIQUE = """
MATCH (t:Technique)
WHERE t.technique_id = $tid OR t.name CONTAINS $name
OPTIONAL MATCH (t)<-[:USES|EMPLOYS]-(actor)
OPTIONAL MATCH (t)-[:EXPLOITS]->(vuln:Vulnerability)
RETURN t.technique_id AS tid, t.name AS name, t.tactic AS tactic,
       t.description AS description,
       COLLECT(DISTINCT actor.name) AS used_by,
       COLLECT(DISTINCT vuln.cve_id) AS related_cves
"""

CYPHER_UPSERT_NODE = """
MERGE (n:{label} {{stix_id: $stix_id}})
SET n += $props, n.updated_at = datetime()
RETURN n.stix_id AS id
"""


@dataclass
class KGRecord:
    """A record returned from graph queries."""
    entity: str = ""
    relationship: str = ""
    related: str = ""
    technique_id: str = ""
    confidence: float = 0.0
    source: str = ""
    properties: dict[str, Any] = field(default_factory=dict)


class CyberKG:
    """
    Neo4j-backed CTI Knowledge Graph with NetworkX fallback.

    Connects to Neo4j on init. If unavailable, all operations
    transparently fall back to the in-memory KGBuilderAgent.
    """

    def __init__(self) -> None:
        self._driver: Any = None
        self._neo4j_available = False
        self._connect()

    # ── Connection ───────────────────────────────────────────────

    def _connect(self) -> None:
        try:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS),
                max_connection_lifetime=300,
            )
            self._driver.verify_connectivity()
            self._neo4j_available = True
            self._init_schema()
            log.info("neo4j_connected", uri=NEO4J_URI)
        except Exception as e:
            self._neo4j_available = False
            log.warning("neo4j_unavailable_using_networkx", error=str(e))

    def _init_schema(self) -> None:
        """Create constraints and indexes on first connect."""
        with self._driver.session() as s:
            for cypher in CYPHER_INIT_CONSTRAINTS:
                try:
                    s.run(cypher)
                except Exception:
                    pass

    def close(self) -> None:
        if self._driver:
            self._driver.close()

    @property
    def is_neo4j(self) -> bool:
        return self._neo4j_available

    # ── Core CRUD ────────────────────────────────────────────────

    def add_triple(
        self,
        subject: str,
        predicate: str,
        obj: str,
        technique_id: str = "",
        technique_name: str = "",
        confidence: float = 0.7,
        source: str = "",
        triple_id: str = "",
        **extra,
    ) -> bool:
        """Add a (subject, predicate, object) triple to the graph."""
        if not self._neo4j_available:
            return self._fallback_add_triple(
                subject, predicate, obj, technique_id, technique_name,
                confidence, source, triple_id,
            )

        params = {
            "subject": subject, "predicate": predicate, "object": obj,
            "technique_id": technique_id, "technique_name": technique_name,
            "confidence": confidence, "source": source, "triple_id": triple_id,
        }
        try:
            with self._driver.session() as s:
                s.run(CYPHER_ADD_TRIPLE, params)
            return True
        except Exception as e:
            log.warning("neo4j_add_triple_failed", error=str(e))
            return self._fallback_add_triple(
                subject, predicate, obj, technique_id, technique_name,
                confidence, source, triple_id,
            )

    def query_related(self, entity: str, hops: int = 2) -> list[KGRecord]:
        """Traverse the graph from entity up to N hops."""
        if not self._neo4j_available:
            return self._fallback_query_related(entity, hops)

        try:
            with self._driver.session() as s:
                # Try APOC path first, fall back to simple pattern
                try:
                    result = s.run(CYPHER_QUERY_RELATED,
                                   {"entity": entity, "hops": hops})
                except Exception:
                    result = s.run(CYPHER_QUERY_RELATED_SIMPLE,
                                   {"entity": entity, "hops": hops})

                records = []
                for rec in result:
                    records.append(KGRecord(
                        entity=rec.get("entity", ""),
                        relationship=rec.get("relationship", ""),
                        related=rec.get("related", ""),
                        technique_id=rec.get("technique_id", ""),
                        confidence=rec.get("confidence", 0.0) or 0.0,
                        source=rec.get("source", ""),
                    ))
                return records
        except Exception as e:
            log.warning("neo4j_query_failed", error=str(e))
            return self._fallback_query_related(entity, hops)

    def get_attack_chain(
        self, actor: str, start_tid: str = "",
    ) -> dict[str, Any]:
        """Find attack chains: initial access → exfiltration shortest path."""
        if not self._neo4j_available:
            return {"actor": actor, "ttps": [], "attack_paths": []}

        try:
            with self._driver.session() as s:
                # First get actor's TTPs
                ttps = s.run(CYPHER_TTPS_BY_ACTOR, {"actor": actor})
                ttp_list = [{"id": r["tid"], "name": r["name"],
                             "tactic": r.get("tactic", "")}
                            for r in ttps]

                # Then find shortest attack path
                paths = s.run(CYPHER_ATTACK_PATH, {"start_tid": start_tid})
                path_list = [{"chain": r["chain"], "rels": r["rels"],
                              "hops": r["hops"]} for r in paths]

                return {"actor": actor, "ttps": ttp_list, "attack_paths": path_list}
        except Exception as e:
            log.warning("attack_chain_query_failed", error=str(e))
            return {"actor": actor, "ttps": [], "attack_paths": []}

    def search_by_technique(self, technique_id: str) -> list[dict[str, Any]]:
        """Find a technique and its related actors/CVEs."""
        if not self._neo4j_available:
            return self._fallback_search_technique(technique_id)

        try:
            with self._driver.session() as s:
                result = s.run(CYPHER_SEARCH_TECHNIQUE,
                               {"tid": technique_id, "name": technique_id})
                return [dict(r) for r in result]
        except Exception as e:
            log.warning("technique_search_failed", error=str(e))
            return self._fallback_search_technique(technique_id)

    def query_recent(self, days: int = 30) -> list[dict[str, Any]]:
        """
        Temporal query: find CVEs exploited in the last N days.
        Core RO2 requirement for temporal currency.
        """
        if not self._neo4j_available:
            return []

        try:
            with self._driver.session() as s:
                result = s.run(CYPHER_RECENT_CVES, {"days": days})
                return [dict(r) for r in result]
        except Exception as e:
            log.warning("recent_query_failed", error=str(e))
            return []

    # ── STIX Ingestion ───────────────────────────────────────────

    def upsert_from_stix(self, stix_bundle: dict[str, Any]) -> int:
        """
        Ingest a STIX 2.1 bundle into the graph.
        Creates/updates nodes for each object and relationships.
        Returns count of upserted objects.
        """
        objects = stix_bundle.get("objects", [])
        if not objects:
            return 0

        count = 0
        rels_to_add: list[dict] = []

        for obj in objects:
            obj_type = obj.get("type", "")
            stix_id = obj.get("id", "")

            if obj_type == "relationship":
                rels_to_add.append(obj)
                continue

            label = self._stix_type_to_label(obj_type)
            if not label:
                continue

            props = {
                "stix_id": stix_id,
                "name": obj.get("name", stix_id),
                "description": obj.get("description", "")[:500],
                "created": obj.get("created", ""),
                "modified": obj.get("modified", ""),
                "source_url": "",
                "tlp_level": "white",
                "confidence_score": obj.get("confidence", 0.7),
            }

            # Extract technique_id for ATT&CK patterns
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    props["technique_id"] = ref.get("external_id", "")
                    props["source_url"] = ref.get("url", "")

            # Extract CVE ID for vulnerabilities
            if obj_type == "vulnerability":
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "cve":
                        props["cve_id"] = ref.get("external_id", "")

            # Extract tactic from kill chain
            for kc in obj.get("kill_chain_phases", []):
                if kc.get("kill_chain_name") == "mitre-attack":
                    props["tactic"] = kc["phase_name"].replace("-", " ").title()

            if self._upsert_node(label, props):
                count += 1

        # Process relationships
        for rel in rels_to_add:
            self._upsert_relationship(rel)
            count += 1

        log.info("stix_bundle_ingested", objects=count, total=len(objects))
        return count

    def _upsert_node(self, label: str, props: dict) -> bool:
        if not self._neo4j_available:
            return False
        try:
            cypher = CYPHER_UPSERT_NODE.replace("{label}", label)
            with self._driver.session() as s:
                s.run(cypher, {"stix_id": props["stix_id"], "props": props})
            return True
        except Exception as e:
            log.debug("upsert_node_failed", label=label, error=str(e))
            return False

    def _upsert_relationship(self, rel: dict) -> None:
        if not self._neo4j_available:
            return
        rel_type = rel.get("relationship_type", "related-to").upper().replace("-", "_")
        src = rel.get("source_ref", "")
        tgt = rel.get("target_ref", "")
        if not src or not tgt:
            return
        try:
            cypher = (
                "MATCH (s {stix_id: $src}), (t {stix_id: $tgt}) "
                f"MERGE (s)-[r:{rel_type}]->(t) "
                "SET r.stix_id = $rid, r.last_seen = datetime()"
            )
            with self._driver.session() as s:
                s.run(cypher, {"src": src, "tgt": tgt,
                               "rid": rel.get("id", "")})
        except Exception:
            pass

    @staticmethod
    def _stix_type_to_label(stix_type: str) -> str:
        return {
            "threat-actor": "ThreatActor",
            "intrusion-set": "ThreatActor",
            "campaign": "Campaign",
            "attack-pattern": "Technique",
            "malware": "Malware",
            "tool": "Tool",
            "vulnerability": "Vulnerability",
            "indicator": "IOC",
            "infrastructure": "DataSource",
        }.get(stix_type, "")

    # ── Migration: NetworkX → Neo4j ──────────────────────────────

    def migrate_from_networkx(self, kg_builder) -> int:
        """
        Load all triples from the in-memory KGBuilderAgent into Neo4j.
        Call on startup to bootstrap the graph from existing data.
        """
        if not self._neo4j_available:
            log.warning("migration_skipped_neo4j_unavailable")
            return 0

        count = 0
        for triple in kg_builder.triples:
            ok = self.add_triple(
                subject=triple.subject,
                predicate=triple.predicate,
                obj=triple.obj,
                technique_id=triple.technique_id,
                technique_name=triple.technique_name,
                confidence=triple.confidence,
                source=triple.source,
                triple_id=triple.id,
            )
            if ok:
                count += 1

        log.info("networkx_to_neo4j_migration", migrated=count,
                 total=len(kg_builder.triples))
        return count

    # ── NetworkX Fallback Methods ────────────────────────────────

    def _get_kg_builder(self):
        from agents.kg_builder import get_kg_builder
        return get_kg_builder()

    def _fallback_add_triple(self, subject, predicate, obj,
                             technique_id, technique_name,
                             confidence, source, triple_id) -> bool:
        from agents.kg_builder import Triple
        kg = self._get_kg_builder()
        t = Triple(
            subject=subject, predicate=predicate, obj=obj,
            technique_id=technique_id, technique_name=technique_name,
            confidence=confidence, source=source,
        )
        if t.id not in kg.triple_index:
            kg.triples.append(t)
            kg.triple_index[t.id] = t
        return True

    def _fallback_query_related(self, entity: str, hops: int) -> list[KGRecord]:
        kg = self._get_kg_builder()
        neighbors = kg.get_neighbors(entity, hops=hops)
        return [
            KGRecord(
                entity=t.subject, relationship=t.predicate, related=t.obj,
                technique_id=t.technique_id, confidence=t.confidence,
                source=t.source,
            )
            for t in neighbors
        ]

    def _fallback_search_technique(self, technique_id: str) -> list[dict]:
        kg = self._get_kg_builder()
        results = []
        for t in kg.triples:
            if t.technique_id == technique_id:
                results.append({
                    "tid": t.technique_id, "name": t.technique_name,
                    "subject": t.subject, "object": t.obj,
                })
        return results

    # ── Stats ────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        if not self._neo4j_available:
            kg = self._get_kg_builder()
            return {"backend": "networkx", **kg.get_graph_stats()}

        try:
            with self._driver.session() as s:
                nodes = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
                rels = s.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
                labels = s.run(
                    "MATCH (n) RETURN DISTINCT labels(n) AS l, count(n) AS c"
                )
                label_counts = {str(r["l"]): r["c"] for r in labels}
            return {
                "backend": "neo4j",
                "total_nodes": nodes,
                "total_relationships": rels,
                "label_counts": label_counts,
            }
        except Exception:
            return {"backend": "neo4j", "error": "query_failed"}


# ── Singleton ────────────────────────────────────────────────────────
_cyber_kg: CyberKG | None = None


def get_cyber_kg() -> CyberKG:
    global _cyber_kg
    if _cyber_kg is None:
        _cyber_kg = CyberKG()
    return _cyber_kg
