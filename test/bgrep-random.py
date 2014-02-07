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
	
	bgrep_res = subprocess.Popen([BGREP, search.encode('hex'), filename], stdout=subprocess.PIPE).communicate()[0]
	
	expected_res = ''.join(["%s: %016x\n" % (filename, i) for i in results])
	
	if bgrep_res != expected_res:
		print "search: %s" % search.encode('hex')
		open("res_expected", "w").write(expected_res)
		open("res_bgrep", "w").write(bgrep_res)
		assert False

while True:
	datalen = random.randint(0, 1024*1024)
	searchlen = random.randint(1, 50)
#	print datalen, searchlen
	test_bgrep(datalen, searchlen)
