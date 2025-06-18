# quick_test.py
import changtin, oscs, qianxin, threatbook, cisa
kw = "Kafka Connect 任意文件读取漏洞"
print("长亭:", len(changtin.search_changtin(kw)))
print("OSCS :", len(oscs.search_oscs(kw)))
print("奇安信:", len(qianxin.search_qianxin(kw)))
print("TB   :", len(threatbook.search_threatbook(kw)))
print("CISA :", len(cisa.search_cisa(kw)))
