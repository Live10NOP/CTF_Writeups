# Instructions

REPORT: A Client forgot his Password... again.
Could you get it for me? He has a users account and his Lname is Miller if that helps at all.
Oh! and Ken was saying something about a new table called passwd; said it was better to separate things

https://challenges.neverlanctf.com:1155

# Solution

We start by obtaining an ID for the user Miller that we can use to find the appropriate entry in the password table.
We use the following SQL query for this purpose: `SELECT * FROM users`

The following table is returned
```
id  Username  Fname  Lname    Email
1   John      John   Hancock  WhyDoYouWantMy@email.com
2   JimWill   Jimmy  Willman  SQL@example.com
3   Captin    Jack   sparrow  pirates@carribean.com
4   N30	      Zane   Durkin   info@neverlanctf.com
5   DisUser   Tom    Miller   Miller@example.com
```

In the table above, we can see that the user with last name Miller has the ID 5.
Next, we retrieve the `passwd` table with the query: `SELECT * FROM passwd`
```
id  user_id  Password
1   1        Tm9wZS4uLiBXcm9uZyB1c2Vy
2   5        ZmxhZ3tXMWxsX1kwdV9KMDFOX00zP30=
3   2        Tm9wZS4uLiBXcm9uZyB1c2Vy
4   3        Tm9wZS4uLiBXcm9uZyB1c2Vy
5   4        Tm9wZS4uLiBXcm9uZyB1c2Vy
```

The base64 encoded password of the user with ID 5 is `ZmxhZ3tXMWxsX1kwdV9KMDFOX00zP30=`.
We decode this to find the flag.

# Flag
flag{W1ll_Y0u_J01N_M3?}
