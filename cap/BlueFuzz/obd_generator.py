from random import randint
import random
import string

def _gen(size=6, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))

def _genATstring():
	length = randint(1,6)
	
	stringa = "AT" + _gen(length) + '\r'	
	return stringa
	
def _genNumber():
	if randint(0,1) == 0:
		return "0" + str(randint(0,999))
	else:
		return randint(0,99999)
		
def _getRandomData():
	length = randint(1,20)
	return _gen(length, string.printable)
	
def generator():
	index = _gen(1,"12312")
	
	# 40% of probability
	if index == "1":
		result = _genATstring()
	# 40% of probability
	elif index == "2":
		result = _genNumber()
	# 20% of probability
	else:
		result = _getRandomData()
	return str(result)



