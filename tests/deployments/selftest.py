#!/usr/bin/env python3
"""Cheap structural tests for the deployment harness; pulls no images."""

from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

import harness
from lib import (
    ComposeProject,
    DeploymentError,
    ROOT,
    validate_bind_source,
    validate_build_context,
)


class DeploymentHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenarios = harness.load_scenarios()

    def test_nightly_has_exactly_one_case_per_mode_scenario(self) -> None:
        cases = harness.choose_cases(
            self.scenarios,
            profile="nightly",
            rng=random.Random(1),
            sample_count=8,
            only=None,
        )
        self.assertEqual(
            {case.scenario.identifier for case in cases},
            {scenario.identifier for scenario in self.scenarios if scenario.nightly},
        )

    def test_sample_is_reproducible_and_stratified(self) -> None:
        first = harness.choose_cases(
            self.scenarios,
            profile="sample",
            rng=random.Random(8675309),
            sample_count=len(self.scenarios),
            only=None,
        )
        second = harness.choose_cases(
            self.scenarios,
            profile="sample",
            rng=random.Random(8675309),
            sample_count=len(self.scenarios),
            only=None,
        )
        self.assertEqual(first, second)
        self.assertEqual(
            {case.scenario.identifier for case in first},
            {scenario.identifier for scenario in self.scenarios},
        )

    def test_every_combination_is_reachable_by_sampling(self) -> None:
        expected = {
            case.identifier
            for scenario in self.scenarios
            for case in harness.cases_for_scenario(scenario)
        }
        observed: set[str] = set()
        for seed in range(2000):
            observed.update(
                case.identifier
                for case in harness.choose_cases(
                    self.scenarios,
                    profile="sample",
                    rng=random.Random(seed),
                    sample_count=8,
                    only=None,
                )
            )
            if observed == expected:
                break
        self.assertEqual(observed, expected)

    def test_every_image_is_immutable(self) -> None:
        for scenario in self.scenarios:
            for image in scenario.images:
                self.assertRegex(image, r"^[^:@]+(?:/[^:@]+)*@sha256:[0-9a-f]{64}$")

    def test_every_driver_imports(self) -> None:
        for scenario in self.scenarios:
            self.assertTrue(callable(harness.import_driver(scenario).run))

    def test_bind_mounts_are_confined_to_run_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vapache-deployment-selftest-") as temporary:
            run_dir = Path(temporary)
            safe = run_dir / "application"
            safe.mkdir()
            validate_bind_source(safe, run_dir)
            with self.assertRaises(DeploymentError):
                validate_bind_source(ROOT, run_dir)
            with self.assertRaises(DeploymentError):
                validate_bind_source(ROOT.parent, run_dir)
            with self.assertRaises(DeploymentError):
                validate_bind_source(Path("/tmp"), run_dir)

    def test_staged_builds_are_confined_and_digest_pinned(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vapache-build-selftest-") as temporary:
            run_dir = Path(temporary)
            context = run_dir / "build"
            context.mkdir()
            dockerfile = context / "Dockerfile"
            dockerfile.write_text(
                "# syntax=docker/dockerfile:1@sha256:"
                + "b" * 64
                + "\nFROM example.invalid/app@sha256:"
                + "a" * 64
                + "\n"
            )
            validate_build_context(context, dockerfile, run_dir)
            dockerfile.write_text(
                "# syntax=docker/dockerfile:1\n"
                "FROM example.invalid/app@sha256:" + "a" * 64 + "\n"
            )
            with self.assertRaises(DeploymentError):
                validate_build_context(context, dockerfile, run_dir)
            dockerfile.write_text("FROM example.invalid/app:latest\n")
            with self.assertRaises(DeploymentError):
                validate_build_context(context, dockerfile, run_dir)
            dockerfile.write_text(
                "# syntax=docker/dockerfile:1@sha256:" + "b" * 64 + "\nFROM scratch\n"
            )
            (context / "escape").symlink_to(ROOT)
            with self.assertRaises(DeploymentError):
                validate_build_context(context, dockerfile, run_dir)

    def test_compose_models_enforce_container_isolation(self) -> None:
        by_id = {scenario.identifier: scenario for scenario in self.scenarios}
        with tempfile.TemporaryDirectory(prefix="vapache-compose-selftest-") as temporary:
            run_dir = Path(temporary)
            wordpress = run_dir / "wordpress"
            php_run = run_dir / "php-run"
            wordpress.mkdir()
            php_run.mkdir()
            fpm_config = run_dir / "fpm.conf"
            fpm_config.write_text("[www]\n")
            gitea_data = run_dir / "gitea-data"
            gitea_data.mkdir()
            gitea_passwd = run_dir / "gitea.passwd"
            gitea_group = run_dir / "gitea.group"
            gitea_passwd.write_text("runner:x:1000:1000::/data/gitea:/sbin/nologin\n")
            gitea_group.write_text("runner:x:1000:\n")
            drupal_root = run_dir / "drupal"
            drupal_php_run = run_dir / "drupal-php-run"
            drupal_root.mkdir()
            drupal_php_run.mkdir()
            drupal_fpm = run_dir / "drupal-fpm.conf"
            drupal_fpm.write_text("[www]\n")
            nextcloud_root = run_dir / "nextcloud"
            nextcloud_php_run = run_dir / "nextcloud-php-run"
            nextcloud_root.mkdir()
            nextcloud_php_run.mkdir()
            nextcloud_fpm = run_dir / "nextcloud-fpm.conf"
            nextcloud_fpm.write_text("[www]\n")
            jenkins_init = run_dir / "jenkins-security.groovy"
            jenkins_init.write_text("// self-test fixture\n")
            cases = (
                (
                    by_id["wordpress-fpm"],
                    {
                        "WORDPRESS_ROOT": str(wordpress),
                        "PHP_RUN": str(php_run),
                        "FPM_CONFIG": str(fpm_config),
                    },
                ),
                (
                    by_id["grafana-proxy"],
                    {
                        "GRAFANA_PORT": "30999",
                        "GRAFANA_ROOT_URL": "http://127.0.0.1:30998/grafana/",
                        "GRAFANA_SUBPATH": "true",
                        "GRAFANA_HEALTH_PATH": "/grafana",
                    },
                ),
                (
                    by_id["gitea-proxy"],
                    {
                        "HOST_UID": "1000",
                        "HOST_GID": "1000",
                        "GITEA_DATA": str(gitea_data),
                        "GITEA_PASSWD": str(gitea_passwd),
                        "GITEA_GROUP": str(gitea_group),
                        "GITEA_PORT": "30997",
                        "GITEA_HEALTH_PATH": "",
                    },
                ),
                (
                    by_id["drupal-fpm"],
                    {
                        "DRUPAL_ROOT": str(drupal_root),
                        "PHP_RUN": str(drupal_php_run),
                        "FPM_CONFIG": str(drupal_fpm),
                    },
                ),
                (
                    by_id["nextcloud-fpm"],
                    {
                        "NEXTCLOUD_ROOT": str(nextcloud_root),
                        "PHP_RUN": str(nextcloud_php_run),
                        "FPM_CONFIG": str(nextcloud_fpm),
                    },
                ),
                (
                    by_id["jenkins-proxy"],
                    {
                        "JENKINS_PREFIX": "/jenkins",
                        "JENKINS_INIT": str(jenkins_init),
                    },
                ),
                (
                    by_id["jupyterlab-proxy"],
                    {
                        "JUPYTER_BASE_URL": "/jupyter/",
                        "JUPYTER_TOKEN": "selftest-token",
                    },
                ),
                (
                    by_id["minio-proxy"],
                    {
                        "MINIO_ROOT_USER": "selftest-admin",
                        "MINIO_ROOT_PASSWORD": "selftest-password-42",
                    },
                ),
            )
            for scenario, environment in cases:
                ComposeProject(
                    compose_file=scenario.path / "compose.yml",
                    project=f"selftest_{scenario.identifier}",
                    run_dir=run_dir,
                    env=environment,
                    images=scenario.images,
                    artifact_dir=run_dir / "artifacts",
                ).validate()

            wagtail_media = run_dir / "wagtail-media"
            wagtail_media.mkdir()
            wagtail = by_id["wagtail-proxy"]
            local_wagtail = "vapache-deployment-selftest-wagtail:local"
            ComposeProject(
                compose_file=wagtail.path / "compose.yml",
                project="selftest_wagtail",
                run_dir=run_dir,
                env={
                    "WAGTAIL_IMAGE": local_wagtail,
                    "WAGTAIL_MEDIA": str(wagtail_media),
                    "WAGTAIL_WORKERS": "2",
                },
                images=wagtail.images + (local_wagtail,),
                artifact_dir=run_dir / "artifacts",
            ).validate()

            bugzilla_root = run_dir / "bugzilla"
            bugzilla_run = run_dir / "bugzilla-run"
            bugzilla_root.mkdir()
            bugzilla_run.mkdir()
            bugzilla = by_id["bugzilla-fastcgi"]
            local_bugzilla = "vapache-deployment-selftest-bugzilla:local"
            ComposeProject(
                compose_file=bugzilla.path / "compose.yml",
                project="selftest_bugzilla",
                run_dir=run_dir,
                env={
                    "BUGZILLA_IMAGE": local_bugzilla,
                    "BUGZILLA_ROOT": str(bugzilla_root),
                    "BZ_URLBASE": "http://127.0.0.1:30996/",
                    "FCGI_RUN": str(bugzilla_run),
                    "VAPACHE_SOCKET_GID": "1000",
                },
                images=bugzilla.images + (local_bugzilla,),
                artifact_dir=run_dir / "artifacts",
            ).validate()


if __name__ == "__main__":
    unittest.main()

