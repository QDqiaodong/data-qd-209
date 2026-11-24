from obj_reloc import process
from obj_reloc.io import load,publish
if __name__=='__main__':
 r=process(load('fixtures/input.json'));publish('run/sample.json',r);print(r['summary'])
