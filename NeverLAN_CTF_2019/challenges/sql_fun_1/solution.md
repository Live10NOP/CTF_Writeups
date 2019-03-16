# Instructions

REPORT: 'My Customer forgot his Password. His Fname is Jimmy. Can you get his password for me? It should be in the users table'

# Solution

We simply need to create a SQL query that will return the Jimmy's password.
I used the following:
```
SELECT Password FROM users WHERE Fname="Jimmy"
```

# Flag
flag{SQL_F0r_Th3_W1n}
