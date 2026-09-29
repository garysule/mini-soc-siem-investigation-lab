import unittest
from detect import detect

class DetectionTests(unittest.TestCase):
    def test_bruteforce_and_success(self):
        logs = [
            {"timestamp":"2026-09-29T08:00:00","log_type":"auth","user":"x","src_ip":"1.1.1.1","event":"login_failed","success":"false","host":"pc","process":"-"},
            {"timestamp":"2026-09-29T08:00:10","log_type":"auth","user":"x","src_ip":"1.1.1.1","event":"login_failed","success":"false","host":"pc","process":"-"},
            {"timestamp":"2026-09-29T08:00:20","log_type":"auth","user":"x","src_ip":"1.1.1.1","event":"login_failed","success":"false","host":"pc","process":"-"},
            {"timestamp":"2026-09-29T08:00:30","log_type":"auth","user":"x","src_ip":"1.1.1.1","event":"login_failed","success":"false","host":"pc","process":"-"},
            {"timestamp":"2026-09-29T08:00:40","log_type":"auth","user":"x","src_ip":"1.1.1.1","event":"login_success","success":"true","host":"pc","process":"-"},
        ]
        alerts = detect(logs)
        rules = {a["rule"] for a in alerts}
        self.assertIn("Brute-force threshold", rules)
        self.assertIn("Success after repeated failures", rules)

if __name__ == "__main__":
    unittest.main()
