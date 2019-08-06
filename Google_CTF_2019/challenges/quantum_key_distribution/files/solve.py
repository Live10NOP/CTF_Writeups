import request
import time
import os

import numpy
import json

def main():
	my_basis, my_qubits, server_basis, server_announcement = request.get_data()
	measured_bits = measure(unmarshal(my_qubits), my_basis)
	measured_bits2 = measure(unmarshal(my_qubits), my_basis)
	assert measured_bits == measured_bits2, "{}\n{}".format(measured_bits, measured_bits2)
	binary_key_full, err = compare_bases_and_generate_key(my_basis, server_basis, measured_bits)
	if err != None:
		print(err)
		return
	assert len(server_announcement) == 32
	binary_key = binary_key_full[:len(binary_key_full) - (len(binary_key_full) % 8)]
	assert len(binary_key) % 8 == 0
	#print(key)
	hex_key = ""
	for i in range(0, len(binary_key), 8):
		hex_key += "{:02x}".format(int(binary_key[i:i+8], 2))
	#print("Generate key: {}".format(hex_key))
	#print("Server key:   {}".format(server_announcement))
	#key = ""
	#for i in range(0, len(server_announcement), 2):
	#	b_h = server_announcement[i:i+2]
	#	b = int(b_h, 16)
	#	key += binary_key_full[b]
	#print(key)
	hex_key_short = hex_key[:len(server_announcement)]

	key = ""
	for i in range(0, len(server_announcement), 2):
		key += "{:02x}".format(int(server_announcement[i:i+2], 16) ^ int(hex_key_short[i:i+2], 16))
	print(key)


# SERVER FUNCTIONS
	
def rotate_45(qubit):
	return qubit * complex(0.707, -0.707)	


def measure(rx_qubits, basis):
	measured_bits = ""
	for q, b in zip(rx_qubits, basis):
		if b == 'x':
			q = rotate_45(q)
		probability_zero = round(pow(q.real, 2), 1)
		probability_one = round(pow(q.imag, 2), 1)
		measured_bits += str(numpy.random.choice(numpy.arange(0, 2), p=[probability_zero, probability_one]))
	return measured_bits

def compare_bases_and_generate_key(tx_bases, rx_bases, measure):
	"""Compares TX and RX bases and return the selected bits."""
	if not (len(tx_bases) == len(rx_bases) == len(measure)):
		return None, "tx_bases(%d), rx_bases(%d) and measure(%d) must have the same length." % (len(tx_bases), len(rx_bases), len(measure))
	ret = ''
	for bit, tx_base, rx_base in zip(measure, tx_bases, rx_bases):
		if tx_base == rx_base:
			ret += bit
	return ret, None

def unmarshal(qubits):
	return [complex(q['real'], q['imag']) for q in qubits]

	

if __name__ == "__main__":
	main()
