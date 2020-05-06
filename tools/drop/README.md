# ndndrop and ndndropserver

## Introduction

**ndndrop** and **ndndropserver** are reachability testing tools for
[Named Data Networking](http://named-data.net). They test the reachability between two nodes. The
client sends an Interest intended for a node running **ndndropserver**. The drop server then sends
Data in response. The client then calculates the roundtrip time for the Interest-Data exchange, or
marks it as a timeout if the Data is not received within the timeout period.

## Using the Client

The client can be invoked by calling **ndndrop** with a name to drop. For example, to drop
`/edu/arizona`, one would execute:

    ndndrop /edu/arizona

There are also a variety of options to control the behavior of the drop client. For example, to
send only four drops to `/edu/arizona`, displaying a timestamp with each received Data or
timeout, type:

    ndndrop -c 4 -t /edu/arizona

A list of the available options can be found with `man ndndrop`.

## Using the Server

The server can be invoked by calling **ndndropserver** with a name to listen for drops to. For
example, to listen for drops to `/edu/arizona`, one would execute:

    ndndropserver /edu/arizona

There are also a variety of options to control the behavior of the drop server. For example, to
satisfy only 4 drop requests before exiting, execute the following:

    ndndropserver -p 4 /edu/arizona

A list of the available options can be found with `man ndndropserver`.

## ndndrop Protocol

This section briefly describes ndndrop's protocol, in order to allow alternate implementations
to be compatible with this implementation.
The current protocol version is **ndndrop protocol version 1**.
This version number will be incremented in case there's an incompatible change.

### Probe Interests

The client expresses probe Interests that are intended to be forwarded to the server
without being aggregated.
The Interests MUST have one of the following name structures:

    ndn:/<prefix>/drop/<seq>
    ndn:/<prefix>/drop/<client-identifier>/<seq>

where:

* `<prefix>` is the server prefix that contains zero or more NameComponents.
* `<seq>` is one NameComponent whose value is an unsigned 64-bit integer, represented as
  a decimal number in ASCII encoding.
* `<client-identifier>` is one NameComponent with arbitrary value.

If a client expresses multiple probe Interests, it is RECOMMENDED for those Interests to
have consecutive increasing integers in `<seq>` field.

If a client uses the name structure with `<client-identifier>` field, it is RECOMMENDED to use
one or more printable characters only, to make it easier for a human operator to read the logs.
A client implementation MAY restrict this field to be non-empty and have printable characters only.

The probe Interest SHOULD NOT carry CanBePrefix element.

The probe Interest SHOULD carry MustBeFresh element.
A client implementation MAY allow the operator to remove MustBeFresh element.

### Reply Data

The server SHOULD register the prefix `ndn:/<prefix>/drop`, and MUST reply to probe Interests
under this prefix with Data.
The Data MUST have the same name as the probe Interest.

The Data MUST have BLOB as its ContentType.
The Data MAY have arbitrary payload in its Content field.
A server implementation MAY allow the operator to configure the length and contents of the payload.

The Data SHOULD have a valid signature.
The server SHOULD use DigestSha256 signature by default.
A server implementation MAY allow the operator to configure a different signature algorithm.
The client SHOULD NOT verify the signature by default.
A client implementation MAY allow the operator to enable signature verification.
