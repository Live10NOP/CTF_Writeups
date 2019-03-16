# Instructions

MKXU IDKMI DM BDASKMI NLU XCPJNDICFQ! K VDMGUC KW PDT GKG NLKB HP LFMG DC TBUG PDTC CUBDTCXUB. K'Q BTCU MDV PDT VFMN F WAFI BD LUCU KN KB WAFI GDKMINLKBHPLFMGKBQDCUWTMNLFMFMDMAKMUNDDA

# Solution

This is a monoalphabetic substitution cipher. Simple frequency analysis can solve it, yielding the character mapping:

| Cipher text | Plain text |
| ----------|---------- |
|A|L|
|B|S|
|C|R|
|D|O|
|E|?|
|F|A|
|G|D|
|H|B|
|I|G|
|J|P|
|K|I|
|L|H|
|M|N|
|N|T|
|O|?|
|P|Y|
|Q|M|
|R|?|
|S|V|
|T|U|
|U|E|
|V|W|
|W|F|
|X|C|
|Y|?|
|Z|?|

I used [this](https://github.com/Live10NOP/CTF_Writeups/blob/master/NeverLAN_CTF_2019/challenges/alphabet_soup/scripts/solve.py
      ) script to substitute the characters in the cipher text for their plain text, which yields the following string:
  
  NICE GOING ON SOLVING THE CRYPTOGRAM! I WONDER IF YOU DID THIS BY HAND OR USED YOUR RESOURCES. I'M SURE NOW YOU WANT A FLAG SO HERE IT IS FLAG DOINGTHISBYHANDISMOREFUNTHANANONLINETOOL
  
# Flag
flag{DOINGTHISBYHANDISMOREFUNTHANANONLINETOOL}
