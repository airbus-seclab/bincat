def parse_val(s):
    tbvals = dict.fromkeys(["?","_"], 0) 
    val = None
    bdict = { "0x":(16,"f"),
              "0o":(8,"7"),
              "0b":(2,"1") }
    for p in s.split(","):
        if "=" in p:
            lv,rv = p.split("=",1)
            lv = lv.strip()
            rv = rv.strip()
            base,digit = bdict.get(rv[:2],(10,"9"))
            tbvals[lv] |= int(rv, base)
        else:
            p = p.strip()
            
            base,digit = bdict.get(p[:2],(10,"9"))
            if base in [2,4,8,16,32,64]:
                vv = int(p.replace("_","0").replace("?","0"), base)
                vtop = int(p.replace("_","0").replace("?", digit), base)
                vbot = int(p.replace("?","0").replace("_", digit), base)
            else:
                if "?" in p or "_" in p:
                    raise Exception("Cannot put '?' or '_' in base %i" % base)
                vv = int(p, base)
                vtop = vbot = vv
            if val is not None:
                raise Exception("Cannot put several values in the same line")
            val = vv
            tbvals["?"] |= vtop^vv
            tbvals["_"] |= vbot^vv
    top = tbvals["?"]
    bot = tbvals["_"]
    if top & bot:
        raise Exception("bits %#x are set both at top(?) and bottom(_)"%top&bot) 
    return val,tbvals["?"],tbvals["_"]

def val2str(val, vtop, vbot):
    try:
        s = "%#x" % val
        if vtop:
            s+=",?=%#x" % vtop
        if vbot:
            s+=",_=%#x" % vbot
    except:
        s = repr((val, vtop, vbot))
    return s

