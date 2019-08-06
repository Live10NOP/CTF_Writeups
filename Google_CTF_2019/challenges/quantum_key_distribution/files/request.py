import requests
import random
import math
import json

URL = "https://cryptoqkd.web.ctfcompetition.com/qkd/qubits"

BREAK_LIMIT = 10

NUM_QUBITS = 512

def main():
	print(get_data())

def get_data():
	my_data, server_data = send_request()
	break_counter = 0
	while 'error' in server_data:
		print(server_data['error'])
		my_data, server_data = send_request()
		break_counter += 1
		if break_counter > BREAK_LIMIT:
			raise Exception("Could not get the server to respond...:/")

	my_basis = my_data['basis']
	my_qubits = my_data['qubits']
	server_basis = server_data['basis']
	server_announcement = server_data['announcement']

	return my_basis, my_qubits, server_basis, server_announcement

	
	#print("Response:")
	#print(response.text)

def send_request():
	random.seed()
	my_qubits = []
	my_basis = [random.choice('+') for _ in range(NUM_QUBITS)]
	for _ in range(NUM_QUBITS):
		r = float(round(random.random()))
		i = math.sqrt(1.0 - pow(r, 2))
		assert round(pow(r, 2), 1) + round(pow(i, 2), 1) == 1.0, "r: {}, i: {}, (r^2 + i^2 = {})".format(r, i, round(pow(r, 2), 1) + round(pow(i, 2), 1))
		my_qubits.append({'real':r, 'imag':i})
	my_data = {'basis':my_basis, 'qubits':my_qubits}
	#print("Sent:")
	#print(data)
	response = requests.post(URL, json=my_data)
	server_data = json.loads(response.text)
	return my_data, server_data

if __name__ == "__main__":
	main()
