import string
import random
import sys

word = [0, 0, 0, 0, 0, 0, 0, 0]

def make_word(word):
	word[0] = random.choice(string.digits + string.ascii_uppercase)
	word[1] = random.choice(string.digits + string.ascii_uppercase)
	word[2] = random.choice(string.digits + string.ascii_uppercase)
	word[3] = random.choice(string.digits + string.ascii_uppercase)
	word[4] = random.choice(string.digits + string.ascii_uppercase)
	word[5] = random.choice(string.digits + string.ascii_uppercase)
	word[6] = random.choice(string.digits + string.ascii_uppercase)
	word[7] = random.choice(string.digits + string.ascii_uppercase)

	new_word = word[0] + word[1] + word[2] + word[3] + word[4] + word[5] + word[6] + word[7]
	print (new_word)
	return new_word

def make_dictionary(new_word):
	output_wordlist = open(sys.argv[1], 'a')
	output_wordlist.write( new_word + '\n')
	output_wordlist.close()

for i in range(100):
	new_word = make_word(word)
	make_dictionary(new_word)
