<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Quantum Key Distribution</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css">
  </head>
  <body>
    <div class="navbar navbar-default">
      <div class="container">
        <div class="navbar-header">
          <div class="navbar-brand">Quantum Key Distribution - Satellite Key Exchange</div>
        </div>
      </div>
    </div>
    <div class="container">
      <h3>Challenge</h3>
      <div class="media">
        <div class="media-body">
          <p>We are simulating a Quantum satellite that can exchange keys using qubits implementing BB84. You must POST the qubits and basis of measurement to `/qkd/qubits` and decode our satellite response, you can then derive the shared key and decrypt the flag. Send 512 qubits and basis to generate enough key bits.</p>
          <p>This is the server's code:</p>
          <div>
import random<br>
import numpy<br>
<br>
from math import sqrt<br>
from flask import current_app<br>
<br>
def rotate_45(qubit):<br>
&nbsp;&nbsp;return qubit * complex(0.707, -0.707)<br>
<br>
def measure(rx_qubits, basis):<br>
&nbsp;&nbsp;measured_bits = ""<br>
&nbsp;&nbsp;for q, b in zip(rx_qubits, basis):<br>
&nbsp;&nbsp;&nbsp;&nbsp;if b == 'x':<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;q = rotate_45(q)<br>
&nbsp;&nbsp;&nbsp;&nbsp;probability_zero = round(pow(q.real, 2), 1)<br>
&nbsp;&nbsp;&nbsp;&nbsp;probability_one = round(pow(q.imag, 2), 1)<br>
&nbsp;&nbsp;&nbsp;&nbsp;measured_bits += str(numpy.random.choice(numpy.arange(0, 2), p=[probability_zero, probability_one]))<br>
&nbsp;&nbsp;return measured_bits<br>
<br>
def compare_bases_and_generate_key(tx_bases, rx_bases, measure):<br>
&nbsp;&nbsp;"""Compares TX and RX bases and return the selected bits."""<br>
&nbsp;&nbsp;if not (len(tx_bases) == len(rx_bases) == len(measure)):<br>
&nbsp;&nbsp;&nbsp;&nbsp;return None, "tx_bases(%d), rx_bases(%d) and measure(%d) must have the same length." % (len(tx_bases), len(rx_bases), len(measure))<br>
&nbsp;&nbsp;ret = ''<br>
&nbsp;&nbsp;for bit, tx_base, rx_base in zip(measure, tx_bases, rx_bases):<br>
&nbsp;&nbsp;&nbsp;&nbsp;if tx_base == rx_base:<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ret += bit<br>
&nbsp;&nbsp;return ret, None<br>
<br>
def unmarshal(qubits):<br>
&nbsp;&nbsp;return [complex(q['real'], q['imag']) for q in qubits]<br>
<br>
# Receive user's qubits and basis, return the derived key and our basis.<br>
def perform(rx_qubits, rx_basis):<br>
&nbsp;&nbsp;random.seed()<br>
&nbsp;&nbsp;# Multiply the amount of bits in the encryption key by 4 to obtain the amount of basis.<br>
&nbsp;&nbsp;sat_basis = [random.choice('+x') for _ in range(len(current_app.config['ENCRYPTION_KEY'])*16)]<br>
&nbsp;&nbsp;measured_bits = measure(unmarshal(rx_qubits), sat_basis)<br>
&nbsp;&nbsp;binary_key, err = compare_bases_and_generate_key(rx_basis, sat_basis, measured_bits)<br>
&nbsp;&nbsp;if err:<br>
&nbsp;&nbsp;&nbsp;&nbsp;return None, None, err<br>
&nbsp;&nbsp;# ENCRYPTION_KEY is in hex, so multiply by 4 to get the bit length.<br>
&nbsp;&nbsp;binary_key = binary_key[:len(current_app.config['ENCRYPTION_KEY'])*4]<br>
&nbsp;&nbsp;if len(binary_key) < (len(current_app.config['ENCRYPTION_KEY'])*4):<br>
&nbsp;&nbsp;&nbsp;&nbsp;return None, sat_basis, "not enough bits to create shared key: %d  want: %d" % (len(binary_key), len(current_app.config['ENCRYPTION_KEY']))<br>
&nbsp;&nbsp;return binary_key, sat_basis, None<br>
          </div>
          <h4>How to send qubits</h4>
          <p>POST your qubits in JSON format the following way:</p>
          <ul>
            <li><b>basis:</b> List of '+' and 'x' which represents the axis of measurement. Each basis measures one qubit:</li>
            <ul>
              <li>+: Normal axis of measurement.</li>
              <li>x: &#960;/4 rotated axis of measurement.</li>
            </ul>
            <li><b>qubits:</b> List of qubits represented by a dict containing the following keys:</li>
            <ul>
              <li>real: The real part of the complex number (int or float).</li>
              <li>imag: The imaginary part of the complex number (int or float).</li>
            </ul>
          </ul>
          <p>The satellite responds:</p>
          <ul>
            <li><b>basis:</b> List of '+' and 'x' used by the satellite.</li>
            <li><b>announcement:</b> Shared key (in hex), the encryption key is encoded within this key.</li>
          </ul>
        </div>
      </div>
      <h3>Example decryption with hex key 404c368bf890dd10abc3f4209437fcbb:</h3>
      <div>
        <p>echo "404c368bf890dd10abc3f4209437fcbb" > /tmp/plain.key; xxd -r -p /tmp/plain.key > /tmp/enc.key</p>
        <p>echo "U2FsdGVkX182ynnLNxv9RdNdB44BtwkjHJpTcsWU+NFj2RfQIOpHKYk1RX5i+jKO" | openssl enc -d -aes-256-cbc -pbkdf2 -md sha1 -base64 --pass file:/tmp/enc.key</p>
      </div>
      <h3>Flag (base64)</h3>
      <div class="media">
        <div class="media-body">
          <p>U2FsdGVkX19OI2T2J9zJbjMrmI0YSTS+zJ7fnxu1YcGftgkeyVMMwa+NNMG6fGgjROM/hUvvUxUGhctU8fqH4titwti7HbwNMxFxfIR+lR4=</p>
        </div>
      </div>
    </div>
  </body>
</html>
