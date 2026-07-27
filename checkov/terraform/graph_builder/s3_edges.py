from __future__ import annotations

import logging
from typing import Dict, List, Tuple, TYPE_CHECKING

from typing_extensions import TypedDict

from checkov.common.graph.graph_builder import Edge
from checkov.terraform.graph_builder.graph_components.block_types import BlockType

if TYPE_CHECKING:
    from checkov.terraform.graph_builder.local_graph import TerraformLocalGraph

S3_BUCKET_RESOURCE_NAME = "aws_s3_bucket"
S3_BUCKET_REFERENCE_ATTRIBUTE = "bucket"


class S3ConnectedResources(TypedDict):
    bucket_resource_index: int | None
    referenced_vertices: List[Edge]


def build_s3_name_reference_edges(graph: "TerraformLocalGraph") -> None:
    """Supporting reference by name of S3 bucket.

    Finds all edges leading to an S3 bucket resource that were created via an attribute
    reference (e.g. referencing the bucket name/id by string rather than by direct block
    reference), and connects the actual `aws_s3_bucket` resource to those referencing vertices.
    """
    logging.info("Building S3 edges name references")
    edges_count = len(graph.edges)

    # Only build the references when the graph actually contains S3 buckets
    resources_types = graph.get_resources_types_in_graph()
    if S3_BUCKET_RESOURCE_NAME in resources_types:
        # Find all the edges leading to S3 bucket and their references
        s3_buckets_mapping: Dict[Tuple[int, str], S3ConnectedResources] = {}
        for origin_node_index, referenced_vertices in graph.out_edges.items():
            vertex = graph.vertices[origin_node_index]
            if vertex.block_type != BlockType.RESOURCE:
                continue
            bucket_value = str(vertex.attributes.get(S3_BUCKET_REFERENCE_ATTRIBUTE))
            for referenced_vertice in referenced_vertices:
                if referenced_vertice.label == S3_BUCKET_REFERENCE_ATTRIBUTE:
                    key = (referenced_vertice.dest, bucket_value)
                    current = s3_buckets_mapping.get(key, {"bucket_resource_index": None, "referenced_vertices": list()})
                    if vertex.id.startswith(f"{S3_BUCKET_RESOURCE_NAME}."):
                        current["bucket_resource_index"] = origin_node_index
                    else:
                        current["referenced_vertices"].append(referenced_vertice)
                    s3_buckets_mapping[key] = current

        # Create new edges of the found connections
        for (destination, _), mapping in s3_buckets_mapping.items():
            if graph.vertices[destination].block_type in [BlockType.VARIABLE, BlockType.LOCALS]:
                if mapping["bucket_resource_index"] is None:
                    continue
                for reference_vertex in mapping["referenced_vertices"]:
                    graph.create_edge(mapping["bucket_resource_index"], reference_vertex.origin, S3_BUCKET_REFERENCE_ATTRIBUTE, True)

    logging.info(f"Found {len(graph.edges) - edges_count} S3 name references edges")
