# Instructions

Generate a key using Quantum Key Distribution (QKD) algorithm and decrypt the flag.
Further instructions are given on the webpage, mirrored:
<a href="files/webpage.md">here</a>

# Preface

If you are looking for a write-up that will tell you exactly how this challenge works and how to arrive at the solution systematically, this is probably not the write-up for you.
On the other hand, if you want to get an idea of how it is possible to solve a challenge even though you don't understand what's going on, read on.

# Solution

The challenge instructions clearly state that the challenge is about the BB84 quantum key distribution scheme, so it's probably a good idea to start by reading up on that.
I used <a href="https://en.wikipedia.org/wiki/BB84">Wikipedia</a>.

We have to send the server 512 qubits, each a pair of integers where one integer `a` represents the real component and the other `b` the imaginary component, such that `round(pow(a, 2), 1) + round(pow(b, 2), 1) == 1.0`.
Along with the qubits, we need to send 512 characters, each `x`, or `+`, the basis.

The server is going to create its own basis of the same length and then use this basis to measure our qubits to create a bitstring.
Measuring works as follows:
For a qubit with real component `a` and imaginary component `b` with basis `+`, the probability that the bit is `0` is round((a * a), 1) and the probability that the bit is `1` is `round((b * b), 1)`.
On the other hand, when the basis is `x`, the probability for `0` is `round(0.707(a + b), 1)` and the probability that the bit is `1` is `round(0.707(b - a), 1)` (this is just multiplication of complex numbers).
Using these probabilities, a random bit is generated.

This can be seen from the server code:
```python
def measure(rx_qubits, basis):
    measured_bits = ""
    for q, b in zip(rx_qubits, basis):
        if b == 'x':
            q = rotate_45(q)
        probability_zero = round(pow(q.real, 2), 1)
        probability_one = round(pow(q.imag, 2), 1)
        measured_bits += str(numpy.random.choice(numpy.arange(0, 2), p=[probability_zero, probability_one]))
    return measured_bits
```

Here I suspect I may be misunderstanding something, because I don't understand how I'm supposed to recreate the key bits if they are random.
Specifically, the following assertion fails.
```
measured_bits1 = measure(unmarshal(my_qubits), my_basis)
measured_bits2 = measure(unmarshal(my_qubits), my_basis)
assert measured_bits1 == measured_bits2
```
If I cannot recreate a key using my own bits and own bases, how can I do it with the server's basis?

I noticed, however that I can recreate the bits exactly, when I use only `+` bases.
So, we send the server a list of random qubits each with the `+` basis.
The server will return its basis (a random string of `+` and `x`).
Now, we can recreate the key by selecting the measured bits where our bases correspond to the server's.

We use the first couple of bytes of this key in an XOR operation with the server announcement to obtain the decryption key.
The script I used to solve the challenge can be found <a href="files/solve.py">here</a>.

# Flag
CTF{you_performed_a_quantum_key_exchange_with_a_satellite}
