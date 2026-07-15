import os
import tempfile
import unittest

from state_store import StateStore


class StateStoreTests(unittest.TestCase):
    def test_scheduled_tasks_and_jobs_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(os.path.join(tmp, "state.db"))
            store.upsert_scheduled_task(
                "127.0.0.1-TCP",
                "127.0.0.1",
                "TCP",
                15,
                ports="22,80",
                scripts=None,
                discovery="auto",
                created_at="2026-07-15T00:00:00+00:00",
            )
            tasks = store.list_scheduled_tasks()
            self.assertEqual(len(tasks), 1)
            self.assertEqual(tasks[0]["discovery"], "auto")

            store.upsert_job(
                {
                    "job_id": "job-1",
                    "target": "127.0.0.1",
                    "scan_type": "Hybrid",
                    "ports": None,
                    "scripts": None,
                    "discovery": "naabu",
                    "status": "completed",
                    "kind": "immediate",
                    "created_at": "t0",
                    "started_at": "t1",
                    "finished_at": "t2",
                    "error": None,
                    "result_file": "file.json",
                    "result": {"hosts": []},
                }
            )
            loaded = store.get_job("job-1")
            self.assertEqual(loaded["status"], "completed")
            self.assertEqual(loaded["result"], {"hosts": []})
            self.assertEqual(store.list_jobs()[0]["job_id"], "job-1")

            store.delete_scheduled_task("127.0.0.1-TCP")
            self.assertEqual(store.list_scheduled_tasks(), [])

            for index in range(5):
                store.upsert_job(
                    {
                        "job_id": f"j{index}",
                        "target": "t",
                        "scan_type": "Ping",
                        "status": "completed",
                        "kind": "immediate",
                        "created_at": f"t{index}",
                        "finished_at": f"t{index}",
                        "result": None,
                    }
                )
            deleted = store.prune_jobs(2)
            self.assertGreaterEqual(deleted, 3)
            self.assertLessEqual(len(store.list_jobs()), 2)


if __name__ == "__main__":
    unittest.main()
