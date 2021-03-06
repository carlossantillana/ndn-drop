# ndndropretrieve and ndndroppublish

**ndndropretrieve** and **ndndroppublish** **ndndroplist** **crypto** are a set of programs to transfer a file as Data segments.

* **ndndroppublish** is a producer program that reads a file from the standard input, and makes
  it available as NDN Data segments.  It appends version and segment number components
  to the specified name, according to the
  [NDN naming conventions](http://named-data.net/publications/techreports/ndn-tr-22-ndn-memo-naming-conventions/).

* **ndndropretrieve** is a consumer program that fetches Data segments of a file, optionally
  discovering the latest version of the file, and writes the content of the retrieved file to a newly created file named by the file downloaded for example /localhost/demo/dog.png would download as dog.png on consumer's computer

* **ndndroplist** is a producer program that reads a directory, and makes all files in directory
    available as NDN Data segments.  It appends version and segment number components
    to the specified name, according to the
    [NDN naming conventions](http://named-data.net/publications/techreports/ndn-tr-22-ndn-memo-naming-conventions/).

* **crypto** is a decryption program that reads a file, replaces it with a decrypted version of that file.

## Version discovery in ndndropretrieve

If a version component is present at the end of the user-specified NDN name, the provided version
number will be used, without any version discovery process. Otherwise, discovery Interest(s) will
be sent out to fetch metadata of the solicited content from which the Data version will be resolved.
For more information about the packet format and naming convention of Interest and Data packets of
version discovery in ndndropretrieve, please refer to:
[Realtime Data Retrieval (RDR) protocol wiki page](https://redmine.named-data.net/projects/ndn-tlv/wiki/RDR)

## Interest pipeline types in ndndropretrieve

* `fixed`: maintains a fixed-size window of Interests in flight; the window size is configurable
           via a command line option and defaults to 1.

* `aimd` : adjusts the window size via additive-increase/multiplicative-decrease (AIMD).
           By default, it uses a Conservative Window Adaptation, that is, the congestion window
           will be decreased at most once per round-trip-time.

* `cubic`: adjusts the window size similar to the TCP CUBIC algorithm.
           For details about both aimd and cubic please refer to:
           [A Practical Congestion Control Scheme for Named Data
           Networking](https://conferences2.sigcomm.org/acm-icn/2016/proceedings/p21-schneider.pdf)

The default Interest pipeline type is `cubic`.

## Usage examples

### Publishing

The following command will publish the text of the GPL-3 license under the `/localhost/demo/gpl3`
prefix:

    ndndroppublish /localhost/demo/gpl3 < /usr/share/common-licenses/GPL-3

To find the published version you have to start ndndroppublish with the `-p` command line option,
for example:

    ndndroppublish -p /localhost/demo/gpl3 < /usr/share/common-licenses/GPL-3

This command will print the published version to the standard output.

To publish Data with a specific version, you must append a version component to the end of the
prefix. The version component must follow the aforementioned NDN naming conventions.
For example, the following command will publish the version `%FD%00%00%01Qc%CF%17v` of the
`/localhost/demo/gpl3` prefix:

    ndndroppublish /localhost/demo/gpl3/%FD%00%00%01Qc%CF%17v < /usr/share/common-licenses/GPL-3

If the version component is not valid, a new well-formed version will be generated and appended
to the supplied NDN name.

### Retrieval

To retrieve the latest version of a published file, the following command can be used:

    ndndropretrieve /localhost/demo/gpl3

To fetch a specific version of a published file, you can specify the version number at the end of
the name. For example, if the version is known to be `%FD%00%00%01Qc%CF%17v`, the following command
will fetch that exact version of the file (without version discovery):

    ndndropretrieve /localhost/demo/gpl3/%FD%00%00%01Qc%CF%17v

### Listing

The following command will publish the all files in specified directory

    ndndroplist -n /ndnDrop/ -d /home/carlos/Documents/CS217B/ndnDrop

Where -n flag specifies the ndn path which the file will be published. and the -d
  specifies which directory on local computer to post all files from.

For more information, run the programs with `--help` as argument.

### Crypto

The following command will publish the all files in specified directory

    crypto fileToDecrypt

Decrypts and replaces the file.

### How to send files across local network

Run `nfd-start` on both local and remote computers.
On remote computer run  appropriate `ndndroplist` command
On local computer run `nfdc face create udp://<remoteIp>`
On local computer run `nfdc route add /ndnDrop udp://<remoteIp>`
To retrieve data from remote computer: run approriate `ndndropretrieve` command on local computer