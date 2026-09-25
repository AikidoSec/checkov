import os
from unittest import TestCase

from checkov.common.graph.db_connectors.networkx.networkx_db_connector import NetworkxConnector
from checkov.common.output.report import Report
from checkov.runner_filter import RunnerFilter
from checkov.terraform.graph_builder.graph_components.block_types import BlockType
from checkov.terraform.graph_manager import TerraformGraphManager
from checkov.terraform.runner import Runner

TEST_DIRNAME = os.path.dirname(os.path.realpath(__file__))
RESOURCES_DIR = os.path.join(TEST_DIRNAME, "resources/count_indexed_edges")


class TestCountIndexedEdges(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.graph_manager = TerraformGraphManager(db_connector=NetworkxConnector())
        cls.local_graph, _ = cls.graph_manager.build_graph_from_source_directory(
            RESOURCES_DIR, render_variables=True
        )

    def _vertex(self, name: str):
        indices = self.local_graph.vertices_block_name_map[BlockType.RESOURCE].get(name, [])
        self.assertEqual(len(indices), 1, f"expected exactly one vertex named {name}, found {len(indices)}")
        return self.local_graph.vertices[indices[0]]

    def _assert_bucket_edge(self, pab_name: str, bucket_name: str) -> None:
        pab = self._vertex(pab_name)
        bucket = self._vertex(bucket_name)
        matching = [
            edge for edge in self.local_graph.edges
            if self.local_graph.vertices[edge.origin].name == pab.name
            and self.local_graph.vertices[edge.dest].name == bucket.name
            and edge.label == "bucket"
        ]
        self.assertTrue(
            matching,
            f"expected bucket edge from {pab_name} to {bucket_name}, "
            f"edges={[edge.label for edge in self.local_graph.edges if self.local_graph.vertices[edge.origin].name == pab.name]}",
        )

    def test_bool_count_bucket_prefix_connects_pab(self) -> None:
        self._assert_bucket_edge(
            "aws_s3_bucket_public_access_block.replay[0]",
            "aws_s3_bucket.replay[0]",
        )

    def test_bool_count_ne_false_connects_pab(self) -> None:
        self._assert_bucket_edge(
            "aws_s3_bucket_public_access_block.ne_false[0]",
            "aws_s3_bucket.ne_false[0]",
        )

    def test_count_index_pairs_connect_each_instance(self) -> None:
        self._assert_bucket_edge(
            "aws_s3_bucket_public_access_block.multi[0]",
            "aws_s3_bucket.multi[0]",
        )
        self._assert_bucket_edge(
            "aws_s3_bucket_public_access_block.multi[1]",
            "aws_s3_bucket.multi[1]",
        )

    def test_unexpanded_bucket_with_bracket_zero_reference_connects(self) -> None:
        self._assert_bucket_edge(
            "aws_s3_bucket_public_access_block.static[0]",
            "aws_s3_bucket.static",
        )

    def test_interpolated_indexed_reference_connects(self) -> None:
        self._assert_bucket_edge(
            "aws_s3_bucket_public_access_block.interp[0]",
            "aws_s3_bucket.interp[0]",
        )

    def test_versioning_connects_with_bool_count(self) -> None:
        versioning = self._vertex("aws_s3_bucket_versioning.versioned[0]")
        bucket = self._vertex("aws_s3_bucket.versioned[0]")
        matching = [
            edge for edge in self.local_graph.edges
            if self.local_graph.vertices[edge.origin].name == versioning.name
            and self.local_graph.vertices[edge.dest].name == bucket.name
            and edge.label == "bucket"
        ]
        self.assertTrue(matching, "expected versioning resource to connect to its bucket")

    def _run_check(self, check_id: str) -> Report:
        runner = Runner()
        return runner.run(
            root_folder=RESOURCES_DIR,
            runner_filter=RunnerFilter(framework=["terraform"], checks=[check_id]),
        )

    def test_ckv2_aws_6_passes_for_all_count_scenarios(self) -> None:
        report = self._run_check("CKV2_AWS_6")
        passed_resources = {record.resource for record in report.passed_checks}
        expected_passed = {
            "aws_s3_bucket.replay[0]",
            "aws_s3_bucket.ne_false[0]",
            "aws_s3_bucket.multi[0]",
            "aws_s3_bucket.multi[1]",
            "aws_s3_bucket.static",
            "aws_s3_bucket.interp[0]",
            "aws_s3_bucket.versioned[0]",
        }
        self.assertFalse(report.failed_checks, report.failed_checks)
        self.assertTrue(expected_passed.issubset(passed_resources), passed_resources)

    def test_ckv_aws_21_passes_for_versioned_bucket(self) -> None:
        report = self._run_check("CKV_AWS_21")
        passed_resources = {record.resource for record in report.passed_checks}
        self.assertIn("aws_s3_bucket.versioned[0]", passed_resources)
        self.assertFalse(
            [r for r in report.failed_checks if r.resource == "aws_s3_bucket.versioned[0]"],
            report.failed_checks,
        )
