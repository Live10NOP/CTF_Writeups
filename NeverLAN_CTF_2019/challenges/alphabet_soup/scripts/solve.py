cipher_text = "MKXU IDKMI DM BDASKMI NLU XCPJNDICFQ! K VDMGUC KW PDT GKG NLKB HP LFMG DC TBUG PDTC CUBDTCXUB. K'Q BTCU MDV PDT VFMN F WAFI BD LUCU KN KB WAFI GDKMINLKBHPLFMGKBQDCUWTMNLFMFMDMAKMUNDDA"

key = {
	'A':'L',
	'B':'S',
	'C':'R',
	'D':'O',
	'E':'?',
	'F':'A',
	'G':'D',
	'H':'B',
	'I':'G',
	'J':'P',
	'K':'I',
	'L':'H',
	'M':'N',
	'N':'T',
	'O':'?',
	'P':'Y',
	'Q':'M',
	'R':'?',
	'S':'V',
	'T':'U',
	'U':'E',
	'V':'W',
	'W':'F',
	'X':'C',
	'Y':'?',
	'Z':'?'
}

def main():
	message = ""
	for c in cipher_text:
		if 'A' <= c <= 'Z':
			message += key[c]
		else:
			message += c
	print(cipher_text)
	print(message)
	

if __name__ == "__main__":
	main()
