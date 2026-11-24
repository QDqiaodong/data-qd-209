import unittest,json,copy
from pathlib import Path
from obj_reloc import process
class Regression(unittest.TestCase):
 def test_overlap_writes_and_duplicate_sections(self):
  d=json.loads(Path('fixtures/input.json').read_text());r=copy.deepcopy(d['relocations'][0]);r['id']='second';r['offset']=9;d['relocations'].append(r)
  with self.assertRaises(ValueError):process(d)
  d['relocations'].pop();d['sections'].append(copy.deepcopy(d['sections'][0]))
  with self.assertRaises(ValueError):process(d)
