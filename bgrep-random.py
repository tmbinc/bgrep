#!/usr/bin/python3

import os, subprocess, random

BGREP="../bgrep"

def generate_random(datalen, searchlen):
	data = os.urandom(datalen)
	search = os.urandom(searchlen)
	
	results = []
	for i in range(datalen-searchlen+1):
		if data[i:i+searchlen] == search:
			results.append(i)
	return data, search, results


def test_bgrep(datalen, searchlen):
	data, search, results = generate_random(datalen, searchlen)
	filename = "data"
	open(filename, "wb").write(data)
	
	bgrep_res = subprocess.Popen([BGREP, search.hex(), filename], stdout=subprocess.PIPE).communicate()[0]
	
	expected_res = ''.join(["%s: %08x\n" % (filename, i) for i in results]).encode('ascii')
	
	if bgrep_res != expected_res:
		print("search: %s" % search.hex())
		open("res_expected", "wb").write(expected_res)
		open("res_bgrep", "wb").write(bgrep_res)
		assert False

while True:
	datalen = random.randint(0, 1024*1024)
	searchlen = random.randint(1, 50)
	test_bgrep(datalen, searchlen)
