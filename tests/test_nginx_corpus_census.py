import io
import unittest

from tools.nginx_corpus_census import (
    Provenance,
    census,
    extract_stock_directives_from_text,
    query_stratum,
    read_json_stream,
    validate_result,
)


class NginxCorpusCensusTests(unittest.TestCase):
    def test_query_strata_do_not_call_feature_searches_neutral(self):
        self.assertEqual(query_stratum("nginx language:Nginx"), "neutral")
        self.assertEqual(query_stratum("nginx path:conf.d extension:conf"), "neutral")
        self.assertEqual(query_stratum('"proxy_pass" language:Nginx'), "expanded")

    def test_counts_occurrences_once_per_config_for_prevalence(self):
        metadata = {
            "a.conf": Provenance("o/r1", "nginx language:Nginx", "neutral", "raw", "raw"),
            "b.conf": Provenance("o/r2", '"proxy_pass" language:Nginx', "expanded", "raw", "raw"),
        }
        items = [
            {
                "file": "/tmp/a.conf",
                "config": [
                    {"directive": "http", "args": [], "block": [
                        {"directive": "server", "args": [], "block": [
                            {"directive": "proxy_pass", "args": ["http://a"]},
                            {"directive": "proxy_pass", "args": ["http://b"]},
                        ]}
                    ]},
                ],
            },
            {"file": "/tmp/b.conf", "config": [{"directive": "proxy_pass", "args": ["http://c"]}]},
            {"file": "/tmp/fail.conf", "error": True, "config": []},
        ]
        result = census(items, metadata)
        proxy = next(row for row in result["directives"] if row["name"] == "proxy_pass")
        self.assertEqual(proxy["occurrences"], 3)
        self.assertEqual(proxy["config_count"], 2)
        self.assertEqual(proxy["neutral_occurrences"], 2)
        self.assertEqual(proxy["neutral_config_count"], 1)
        self.assertEqual(proxy["config_percent"], 100.0)
        self.assertEqual(result["population"]["parse_failures"], 1)

        contexts = {row["name"]: row for row in result["contexts"]}
        self.assertEqual(contexts["http/server:proxy_pass"]["occurrences"], 2)
        self.assertEqual(contexts["main:proxy_pass"]["occurrences"], 1)

    def test_pretty_printed_adjacent_json_objects_stream(self):
        source = '{\n  "file":"a",\n  "config":[]\n}\n{"file":"b","config":[]}'
        records = list(read_json_stream(io.StringIO(source), chunk_size=7))
        self.assertEqual([record["file"] for record in records], ["a", "b"])

    def test_json_stream_reports_record_number(self):
        with self.assertRaisesRegex(ValueError, "record 2"):
            list(read_json_stream(io.StringIO('{"file":"a","config":[]}\nnot-json\n'), chunk_size=5))

    def test_extracts_only_command_table_names_from_nginx_source(self):
        source = r'''
        static ngx_command_t ngx_http_example_commands[] = {
            { ngx_string("example_mode"), NGX_HTTP_MAIN_CONF, NULL },
            ngx_null_command
        };
        static ngx_str_t unrelated[] = {
            ngx_string("not_a_directive")
        };
        '''
        self.assertEqual(extract_stock_directives_from_text(source), {"example_mode"})

    def test_refuses_to_silently_skip_an_unrecognized_command_table(self):
        source = 'static ngx_command_t commands[] = { { ngx_string("x"), 0, 0 } };'
        with self.assertRaisesRegex(ValueError, "declarations but parsed"):
            extract_stock_directives_from_text(source)

    def test_result_validation_rejects_impossible_prevalence(self):
        result = census(
            [{"file": "a.conf", "config": [{"directive": "server", "args": []}]}],
            {"a.conf": Provenance("o/r", "nginx language:Nginx", "neutral", "raw", "raw")},
            {"server": ["http/ngx_http_core_module.c"]},
        )
        validate_result(result)
        result["directives"][0]["config_count"] = 2
        with self.assertRaisesRegex(ValueError, "invalid directives config counts"):
            validate_result(result)


if __name__ == "__main__":
    unittest.main()
