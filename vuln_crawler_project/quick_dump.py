# quick_dump.py
import sys, json, datetime as dt, pprint
import changtin, oscs, qianxin, threatbook, cisa

day = sys.argv[1] if len(sys.argv) > 1 else dt.date.today().isoformat()

raw = {
    "changtin": changtin.fetch_changtin(day),
    "oscs": oscs.fetch_oscs(day),
    "qianxin": qianxin.fetch_qianxin(day),
    "threatbook": threatbook.fetch_threatbook(day),
    "cisa": cisa.fetch_cisa(day),
}

for k, v in raw.items():
    print(f"\n=== {k}  {len(v)} item(s) ===")
    for it in v[:3]:          # 只打印前 3 条
        pprint.pprint(vars(it), width=120)
