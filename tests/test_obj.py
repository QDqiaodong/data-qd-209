import json,unittest,copy
from pathlib import Path
from obj_reloc import process
class T(unittest.TestCase):
 def setUp(self):self.d=json.loads(Path('fixtures/input.json').read_text())
 def test_relocate(self):
  r=process(self.d);self.assertEqual(r['symbols']['msg']['address'],8194);self.assertEqual(r['relocations'][0]['bytes'],[2,32])
 def test_addend(self):
  self.d['relocations'][0]['addend']=3;self.assertEqual(process(self.d)['relocations'][0]['value'],8197)
 def test_overflow(self):
  self.d['relocations'][0]['width']=1
  with self.assertRaises(ValueError):process(self.d)
 def test_bad_section_symbol(self):
  for key,val in [('section','x'),('symbol','x')]:
   d=copy.deepcopy(self.d);d['relocations'][0][key]=val
   with self.assertRaises(ValueError):process(d)
 def test_duplicate(self):
  self.d['symbols'].append(self.d['symbols'][0])
  with self.assertRaises(ValueError):process(self.d)
 def test_bounds(self):
  self.d['symbols'][0]['offset']=32
  with self.assertRaises(ValueError):process(self.d)
