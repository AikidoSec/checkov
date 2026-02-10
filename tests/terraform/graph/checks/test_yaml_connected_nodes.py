import os
import unittest
import warnings
from unittest import mock

from checkov.terraform import checks
from .test_yaml_policies import load_yaml_data, get_policy_results


class TestYamlConnectedNodes(unittest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("ignore", category=ResourceWarning)
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        # Force NETWORKX so connected_node behavior is consistent (igraph does not populate it)
        self._env_patch = mock.patch.dict("os.environ", {"CHECKOV_GRAPH_FRAMEWORK": "NETWORKX"}, clear=False)
        self._env_patch.start()

    def tearDown(self) -> None:
        if hasattr(self, "_env_patch"):
            self._env_patch.stop()

    def _find_check_by_connected_resource(self, checks, resource):
        """Find check by connected_node resource (order-independent)."""
        for c in checks:
            if c.connected_node and c.connected_node.get('resource') == resource:
                return c
        return None

    def test_S3BucketEncryption_connected_node(self):
        report = self.get_report("S3BucketEncryption")
        # Order can vary across Python/OS; assert by resource instead of index
        failed_with_conn = [c for c in report.failed_checks if c.connected_node]
        failed_none_conn = [c for c in report.failed_checks if c.connected_node is None]

        assert len(failed_none_conn) == 2  # two with no connected node
        assert len(failed_with_conn) == 3  # bad_sse_1, bad_sse_2, bad_sse_3

        bad_sse_1 = self._find_check_by_connected_resource(report.failed_checks, 'aws_s3_bucket_server_side_encryption_configuration.bad_sse_1')
        assert bad_sse_1 is not None
        assert bad_sse_1.connected_node['file_path'] == '/main.tf'
        assert bad_sse_1.connected_node['file_line_range'] == [163, 172]

        bad_sse_2 = self._find_check_by_connected_resource(report.failed_checks, 'aws_s3_bucket_server_side_encryption_configuration.bad_sse_2')
        assert bad_sse_2 is not None
        assert bad_sse_2.connected_node['file_path'] == '/main.tf'
        assert bad_sse_2.connected_node['file_line_range'] == [174, 182]

        bad_sse_3 = self._find_check_by_connected_resource(report.failed_checks, 'aws_s3_bucket_server_side_encryption_configuration.bad_sse_3')
        assert bad_sse_3 is not None
        assert bad_sse_3.connected_node['file_path'] == '/main.tf'
        assert bad_sse_3.connected_node['file_line_range'] == [184, 195]

        passed_with_conn = [c for c in report.passed_checks if c.connected_node]
        passed_none_conn = [c for c in report.passed_checks if c.connected_node is None]
        assert len(passed_none_conn) == 3
        assert len(passed_with_conn) == 3  # good_sse_1, good_sse_2, good_sse_3

        good_sse_1 = self._find_check_by_connected_resource(report.passed_checks, 'aws_s3_bucket_server_side_encryption_configuration.good_sse_1')
        assert good_sse_1 is not None
        assert good_sse_1.connected_node['file_path'] == '/main.tf'
        assert good_sse_1.connected_node['file_line_range'] == [117, 126]

        good_sse_2 = self._find_check_by_connected_resource(report.passed_checks, 'aws_s3_bucket_server_side_encryption_configuration.good_sse_2')
        assert good_sse_2 is not None
        assert good_sse_2.connected_node['file_path'] == '/main.tf'
        assert good_sse_2.connected_node['file_line_range'] == [128, 137]

        good_sse_3 = self._find_check_by_connected_resource(report.passed_checks, 'aws_s3_bucket_server_side_encryption_configuration.good_sse_3')
        assert good_sse_3 is not None
        assert good_sse_3.connected_node['file_path'] == '/main.tf'
        assert good_sse_3.connected_node['file_line_range'] == [139, 150]

    def test_S3BucketLogging_connected_node(self):
        report = self.get_report("S3BucketLogging")
        assert report.failed_checks[0].connected_node is None

        assert report.passed_checks[0].connected_node is None
        assert report.passed_checks[1].connected_node['file_path'] == '/main.tf'
        assert report.passed_checks[1].connected_node['resource'] == 'aws_s3_bucket_logging.example'
        assert report.passed_checks[1].connected_node['file_line_range'] == [14, 19]

    def get_report(self, dir_name):
        dir_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                f"resources/{dir_name}")
        assert os.path.exists(dir_path)
        policy_dir_path = os.path.dirname(checks.__file__)
        assert os.path.exists(policy_dir_path)
        for root, _, f_names in os.walk(policy_dir_path):
            for f_name in f_names:
                if f_name != f"{dir_name}.yaml":
                    continue
                policy = load_yaml_data(f_name, root)
                assert policy is not None
                with mock.patch.dict('os.environ', {'CHECKOV_GRAPH_FRAMEWORK': 'NETWORKX'}):
                    # connected nodes don't exist in igraph, because they are not needed
                    return get_policy_results(dir_path, policy)
