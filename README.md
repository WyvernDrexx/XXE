# XXE Injection

> **XXE Injection** is a web application security vulnerability which allows malicious attackers to interfere with XML parsing of the web application, typically resulting in the access to the contents of arbitrary files on the system, perform a DOS attack, enumerate internal systems and much more.

XEE Injection arises because of the potential dangerous features that XML parser provides. The features though not needed, might be enabled in the web application, which results in the injection.

## XML: Introduction

XML or _Extensible Markup Language_ is a type of markup language that provides a set of rules for encoding a document that can be read by both humans and machines. The main aspect of XML is to provide ability for inter-communication between machines in a simple manner.

XML documents are simple text files that follow a simple rule ie to define that in a `tag` format.

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

Following the rules we then generate our data,

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

Now `person.dtd` will have,

```xml
  <!ELEMENT person (firstname, lastname, age)>
  <!ELEMENT firstname (#PCDATA)>
  <!ELEMENT lastname (#PCDATA)>
  <!ELEMENT age (#PCDATA)>
```
