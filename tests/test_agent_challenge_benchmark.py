import copy
import unittest
from scripts.benchmark_agent_challenge import metrics, outcome, validate_corpus
import json

class AgentChallengeBenchmarkTests(unittest.TestCase):
    def test_failure_is_not_a_clean_negative(self):
        self.assertEqual(outcome(False,False,['parse error']), 'analysis_error')
        self.assertEqual(metrics([{'outcome':'analysis_error'}])['scored_assertions'],0)
    def test_denominator_preserves_misses_and_false_alarms(self):
        rows=[{'outcome':outcome(e,d)} for e,d in [(True,True),(True,False),(False,True),(False,False)]]
        m=metrics(rows)
        self.assertEqual(m['labeled_assertions'],4)
        self.assertEqual((m['precision'],m['recall']),(0.5,0.5))
    def test_metadata_identity_required(self):
        value={'schema_version':'1.0','cases':[{'id':'demo','suite':'heldout-metadata','path':'tools.json','source':'{"tools":[{"name":"other"}]}','expect':{'AI043':True}}]}
        with self.assertRaises(ValueError):validate_corpus(json.dumps(value))
    def test_path_and_duplicate_rejected(self):
        case={'id':'demo','suite':'heldout-source','path':'worker.py','source':'pass','expect':{'AI014':True}}
        for cases in ([case,copy.deepcopy(case)],[{**case,'path':'../worker.py'}]):
            with self.assertRaises(ValueError):validate_corpus(json.dumps({'schema_version':'1.0','cases':cases}))

if __name__=='__main__':unittest.main()
