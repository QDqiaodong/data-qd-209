from .checks import fields,array,ident,integer

def process(data):
 fields(data,('sections','symbols','relocations'));sections={}
 for s in array(data['sections'],1,100):
  fields(s,('name','base','size'));k=ident(s['name']);sections[k]=(integer(s['base'],0,1_000_000),integer(s['size'],1,100_000))
 symbols={}
 for s in array(data['symbols'],0,1000):
  fields(s,('name','section','offset','global'));k=ident(s['name']);
  if k in symbols:raise ValueError('duplicate symbol')
  sec=ident(s['section']);
  if sec not in sections or not 0<=integer(s['offset'],0,100_000)<sections[sec][1]:raise ValueError('invalid symbol')
  if type(s['global']) is not bool:raise ValueError('global must be bool')
  symbols[k]={'section':sec,'offset':s['offset'],'address':sections[sec][0]+s['offset'],'global':s['global']}
 rel=[]
 for r in array(data['relocations'],0,2000):
  fields(r,('id','section','offset','symbol','addend','width'));k=ident(r['id']);sec=ident(r['section']);sym=ident(r['symbol']);off=integer(r['offset'],0,100_000);add=integer(r['addend'],-1_000_000,1_000_000);width=integer(r['width'],1,8)
  if sec not in sections or sym not in symbols or off+width>sections[sec][1]:raise ValueError('invalid relocation')
  value=symbols[sym]['address']+add
  if not 0<=value<1<< (8*width):raise ValueError('relocation overflow')
  rel.append({'id':k,'section':sec,'offset':off,'symbol':sym,'width':width,'value':value,'bytes':[value>>(8*i)&255 for i in range(width)]})
 return {'symbols':symbols,'relocations':rel,'summary':{'sections':len(sections),'symbols':len(symbols),'relocations':len(rel)}}
