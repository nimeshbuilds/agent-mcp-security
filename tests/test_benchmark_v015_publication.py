"""A publication cannot erase first-blind misses or relabel tuned data as blind."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from argparse import Namespace
from unittest.mock import patch
from scripts import build_benchmark_dashboard as dashboard
from scripts.benchmark_v015_data import validate_challenge
from scripts.build_benchmark_dashboard import challenge_svg
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
D=ROOT/'benchmarks/comparison-v015'

class ChallengePublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report=json.loads((D/'challenge-initial.json').read_bytes())
        cls.corpus=json.loads((D/'heldout-challenge.json').read_bytes())
        cls.corpus_hash=hashlib.sha256((D/'heldout-challenge.json').read_bytes()).hexdigest()
        cls.commit_hash=hashlib.sha256((D/'challenge-commitment.json').read_bytes()).hexdigest()
        cls.implementation=json.loads((D/'initial-freeze.json').read_bytes())['implementation_sha256']
    def check(self,report):
        validate_challenge(report,self.corpus,self.corpus_hash,self.commit_hash,'initial-heldout',self.implementation)
    def test_first_blind_misses_remain_in_the_record(self):
        self.check(self.report)
        self.assertEqual(self.report['invarune']['overall']['false_negative'],12)
        self.assertEqual(self.report['invarune']['overall']['true_positive'],4)
    def test_mutating_counts_cannot_hide_misses(self):
        r=copy.deepcopy(self.report);r['invarune']['overall']['false_negative']=0
        with self.assertRaises(ValueError):self.check(r)
    def test_phase_and_implementation_are_bound(self):
        for field in ['phase','implementation']:
            r=copy.deepcopy(self.report)
            if field=='phase':r['phase']='post-disclosure-development'
            else:r['invarune']['implementation_sha256']='0'*64
            with self.subTest(field=field), self.assertRaises(ValueError):self.check(r)
    def test_case_and_label_cannot_be_dropped_or_rewritten(self):
        for field in ['case','label']:
            r=copy.deepcopy(self.report)
            if field=='case':r['invarune']['cases'].pop()
            else:r['invarune']['cases'][0]['expected']=False
            with self.subTest(field=field), self.assertRaises(ValueError):self.check(r)
    def test_cisco_no_match_is_not_a_safety_verdict(self):
        r=copy.deepcopy(self.report);r['cisco_metadata']['cases'][0]['outcome']='true_negative'
        with self.assertRaises(ValueError):self.check(r)
    def test_explicit_skill_label_revision_preserves_every_source(self):
        a=json.loads((ROOT/'benchmarks/skills_tools_accuracy.json').read_bytes())
        b=json.loads((ROOT/'benchmarks/skills_tools_accuracy-v110.json').read_bytes())
        self.assertEqual([(x['id'],x['source'],x['path']) for x in a['cases']],[(x['id'],x['source'],x['path']) for x in b['cases']])
        changes=[(x['id'],rule) for x,y in zip(a['cases'],b['cases']) for rule in x['expect'] if x['expect'][rule]!=y['expect'][rule]]
        self.assertEqual(changes,[('hierarchy-json-schema-field','AI043')])

    def current_args(self):
        return Namespace(comparison=D,before=D/'accuracy-before.json',after=D/'accuracy-after.json',
                         corpus=ROOT/'benchmarks/static_accuracy.json',preview=False)

    def test_final_publication_retains_first_confirmation_and_legacy_label(self):
        data=dashboard.inputs_for(self.current_args())
        self.assertEqual(data['extensions']['confirmation']['phase'],'initial-heldout')
        self.assertEqual(data['extensions']['confirmation_repeat']['phase'],'presentation-only-repeat')
        self.assertEqual(data['extensions']['confirmation']['invarune']['overall']['false_negative'],2)
        self.assertEqual(data['skills']['overall']['false_positive'],1)
        self.assertEqual(data['extensions']['corrected_after']['overall']['false_positive'],0)
        ET.fromstring(challenge_svg(data['extensions']))

    def test_repeat_cannot_be_rebranded_as_new_blind_or_hide_detector_edits(self):
        original=dashboard.load
        for kind in ('repeat_phase','detector_edit'):
            def corrupt(path,inputs):
                value=original(path,inputs)
                if path.name=='confirmation-final.json' and kind=='repeat_phase':
                    value=copy.deepcopy(value);value['phase']='initial-heldout'
                if path.name=='presentation-only-change.json' and kind=='detector_edit':
                    value=copy.deepcopy(value);value['changed_modules']['analyzer.py']={}
                return value
            with self.subTest(kind=kind),patch.object(dashboard,'load',side_effect=corrupt),self.assertRaises(ValueError):
                dashboard.inputs_for(self.current_args())

if __name__=='__main__':unittest.main()
