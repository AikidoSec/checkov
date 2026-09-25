import tempfile
import unittest
from pathlib import Path

from checkov.kubernetes.parser.k8_yaml import load
from checkov.kubernetes.runner import Runner
from checkov.runner_filter import RunnerFilter

EXAMPLES_DIR = Path(__file__).parent / "examples"

MINIMAL_DEPLOYMENT = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  annotations:
    force-redeploy: '{placeholder}'
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0.0
"""


class TestScannerRegistry(unittest.TestCase):
    def test_load_pod(self):
        # given
        file_path = EXAMPLES_DIR / "yaml/busybox.yaml"

        # when
        template, file_lines = load(file_path)

        # then
        assert len(template) == 1
        assert template[0]["apiVersion"] == "v1"
        assert template[0]["kind"] == "Pod"
        assert len(file_lines) == 28


    def test_load_not_k8s_file(self):
        # given
        file_path = EXAMPLES_DIR / "yaml/normal.yaml"

        # when
        template, file_lines = load(file_path)

        # then
        assert template == [{}]
        assert file_lines == []


    def test_load_helm_template_file(self):
        # given
        file_path = EXAMPLES_DIR / "yaml/helm.yaml"

        # when
        template, file_lines = load(file_path)

        # then
        assert template == [{}]
        assert file_lines == []

    def test_load_helm_vars_file(self):
        # given
        file_path = EXAMPLES_DIR / "yaml/helm2.yaml"

        # when
        template, file_lines = load(file_path)

        # then
        assert template == [{}]
        assert file_lines == []

    def test_load_utf8_bom_file(self):
        # given
        file_path = EXAMPLES_DIR / "yaml/busybox_utf8_bom.yaml"

        # when
        template, file_lines = load(file_path)

        # then
        assert len(template) == 1
        assert template[0]["apiVersion"] == "v1"
        assert template[0]["kind"] == "Pod"
        assert len(file_lines) == 28

    def test_load_templating_configmap(self):
        # given
        file_path = EXAMPLES_DIR / "yaml/not_helm_configmap.yaml"

        # when
        template, file_lines = load(file_path)

        # then
        assert len(template) == 1
        assert template[0]["apiVersion"] == "v1"
        assert template[0]["kind"] == "ConfigMap"
        assert len(file_lines) == 8

    def test_load_timestamp_placeholder_deployment(self):
        # CI/CD placeholders like "{{timestamp}}" are valid YAML and must be scanned
        file_path = EXAMPLES_DIR / "yaml/timestamp_annotation_deployment.yaml"

        template, file_lines = load(file_path)

        assert len(template) == 1
        assert template[0]["kind"] == "Deployment"
        assert template[0]["metadata"]["annotations"]["force-redeploy"] == "{{timestamp}}"
        assert len(file_lines) == 19

    def test_load_plain_string_annotation_deployment(self):
        file_path = EXAMPLES_DIR / "yaml/plain_string_annotation_deployment.yaml"

        template, file_lines = load(file_path)

        assert len(template) == 1
        assert template[0]["kind"] == "Deployment"
        assert template[0]["metadata"]["annotations"]["force-redeploy"] == "manual"
        assert len(file_lines) == 19

    def test_plain_string_annotation_still_reports_findings(self):
        templated = EXAMPLES_DIR / "yaml/timestamp_annotation_deployment.yaml"
        plain = EXAMPLES_DIR / "yaml/plain_string_annotation_deployment.yaml"

        templated_report = Runner().run(root_folder="", files=[str(templated)], runner_filter=RunnerFilter())
        plain_report = Runner().run(root_folder="", files=[str(plain)], runner_filter=RunnerFilter())

        templated_failed_ids = sorted(check.check_id for check in templated_report.failed_checks)
        plain_failed_ids = sorted(check.check_id for check in plain_report.failed_checks)

        self.assertTrue(templated_failed_ids)
        self.assertEqual(templated_failed_ids, plain_failed_ids)

    def test_skip_quoted_helm_values_deployment(self):
        file_path = EXAMPLES_DIR / "yaml/quoted_helm_values_deployment.yaml"

        template, file_lines = load(file_path)

        assert template == [{}]
        assert file_lines == []

    def test_placeholder_scan_vs_helm_skip(self):
        scan_placeholders = (
            "{{timestamp}}",
            "{{CI_COMMIT_SHA}}",
            "{{ include \"chart.name\" . }}",
            "manual",
        )
        skip_placeholders = (
            "{{ .Values.timestamp }}",
            "{{ .Release.Name }}",
            "{{- if .Values.enabled }}",
            "{{- with .Values.env }}",
            "{{- end }}",
        )

        for placeholder in scan_placeholders:
            with self.subTest(placeholder=placeholder):
                template, file_lines = self._load_deployment_with_placeholder(placeholder)
                self.assertEqual(template[0]["kind"], "Deployment")
                self.assertTrue(file_lines)

        for placeholder in skip_placeholders:
            with self.subTest(placeholder=placeholder):
                template, file_lines = self._load_deployment_with_placeholder(placeholder)
                self.assertEqual(template, [{}])
                self.assertEqual(file_lines, [])

    @staticmethod
    def _load_deployment_with_placeholder(placeholder: str):
        content = MINIMAL_DEPLOYMENT.format(placeholder=placeholder)
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
            tmp.write(content)
            path = Path(tmp.name)
        try:
            return load(path)
        finally:
            path.unlink()


if __name__ == '__main__':
    unittest.main()
