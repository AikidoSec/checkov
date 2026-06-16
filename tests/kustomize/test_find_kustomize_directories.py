import os
import unittest

from checkov.kustomize.runner import find_kustomize_directories

RESOURCES = os.path.join(os.path.dirname(__file__), "runner", "resources")
NESTED_PATCHES = os.path.join(RESOURCES, "nested_patches")
EXAMPLE = os.path.join(RESOURCES, "example")
KUSTOMIZEGOAT = os.path.join(RESOURCES, "kustomizegoat")


class TestFilterRootKustomizeDirectories(unittest.TestCase):
    def test_nested_patches_root_scan_finds_only_overlay(self):
        """Parent patches live in base/ and overlays/prod/, not in deployments/app/."""
        root = os.path.abspath(NESTED_PATCHES)
        dirs = find_kustomize_directories(root, None, [])
        rel = sorted(os.path.relpath(d, root) for d in dirs)

        self.assertEqual(rel, ["overlays/prod"])

    def test_nested_patches_overlay_scan_unchanged(self):
        overlay = os.path.abspath(os.path.join(NESTED_PATCHES, "overlays", "prod"))
        dirs = find_kustomize_directories(overlay, None, [])
        rel = sorted(os.path.relpath(d, overlay) for d in dirs)

        self.assertEqual(rel, ["."])

    def test_nested_patches_base_scan_finds_only_base(self):
        base = os.path.abspath(os.path.join(NESTED_PATCHES, "base"))
        dirs = find_kustomize_directories(base, None, [])
        rel = sorted(os.path.relpath(d, base) for d in dirs)

        self.assertEqual(rel, ["."])

    def test_kustomizegoat_root_scan_finds_only_overlay(self):
        root = os.path.abspath(KUSTOMIZEGOAT)
        dirs = find_kustomize_directories(root, None, [])
        rel = sorted(os.path.relpath(d, root) for d in dirs)

        self.assertEqual(rel, ["overlays/prod"])

    def test_explicit_file_skips_filtering(self):
        base_kustomization = os.path.join(EXAMPLE, "base", "kustomization.yaml")
        dirs = find_kustomize_directories(None, [base_kustomization], [])
        self.assertEqual(len(dirs), 1)
        self.assertTrue(dirs[0].endswith(os.path.join("base")))

    def test_example_root_scan_excludes_base_referenced_by_overlays(self):
        example_root = os.path.abspath(EXAMPLE)
        dirs = find_kustomize_directories(example_root, None, [])
        rel = {os.path.relpath(d, example_root) for d in dirs}

        self.assertNotIn("base", rel)
        self.assertIn("overlays/prod", rel)
        self.assertIn("no_type", rel)


if __name__ == "__main__":
    unittest.main()
