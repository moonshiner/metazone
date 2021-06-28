# metazone

Metazone is based on Paul Vixie's 2006 paper, and somewhat on the catalog
zones RFC draft.  See my Lightning talk at DNS-OARC 27:

https://indico.dns-oarc.net/event/27/contributions/479/

This is a python3 implementation of ideas I've had regarding metazones,
with a (for now) BIND 9.16+ back end.  The automation around this code isn't
present, but in a different implementation I used nsnotify from:

https://git.uis.cam.ac.uk/x/uis/ipreg/nsnotifyd.git

...in order to trigger metazone validation and configuration generation
on a host after the metazone was updated.  Things like staging,
green/blue rollout, et cetera are not part of this code base.

The YAML describes a set of name servers (which are members of name
server groups), zone groups, and attributes applied at three levels:
global defaults, name server group overrides, and per-zone overrides
(in a zone list).

*metazone.yaml* contains an example YAML file, describing a secondary
DNS grid with a few name server groups and some conditional
forwarding cases.  Since all the host names within it are invalid, you
must run generate_mz.py with the --debug=true flag, which will spoof
repeatable answers to A/AAAA queries.


REQUIRED YAML ENTRIES:


version
host_search_path
defaults
zone_groups
dns_servers
name_server_groups


OPTIONAL ENTRIES:


Almost anything, but unless referenced by something in the required
entries, they'll be ignored.  Examples of useful optional entries:

host_lists
dns_clients
zone_lists



ATTRIBUTE METHODS


Some URL-style method prefixes have special meaning to metazone generation
and interpretation:

*key*: look up this attribute somewhere else in the YAML tree.  Attribute
names are given by mapping the YAML to a dictionary of dictionaries,
with POSIX-style path elements, i.e. "one/two/three" is a reference to
an Attribute named "three" in dictionary "two", which is in turn under
dictionary "one" in the YAML.

*eval*: carefully expose enough python syntax to do expressions.  *eval* is
different if interpreted at generation time vs. client parsing time in what
variables are exposed to the expression.  If you wish to have the client
interpret the eval, use *delay*.

*host*: using the defined host_search_path (which is mandatory to define),
look up short hostnames and place the resulting IP list in the attribute
instead.  At generation time, IPv4 answers are preferred to IPv6 answers
by default, which can be changed with the --preferv4=false flag.
Any hostname that already is fully qualified (trailing dot) will not
invoke the search path.

*collect*: produce the full set of attributes at/under the named YAML key.
For lists, this will add all list members; for dictionaries, all keys.

*delay*: postpone interpretation of this attribute until client parsing
time.  In general, this is used as a prefix for *eval*, *host*, and *key*
to ensure they aren't interpreted early.

*fetch*: not honored at generation time, this is *key* with a implied *delay*.

*b64*: encode the remainder of the string (usually in a YAML block quote)
with base64; this allows sending things thru metazone that are difficult
to quote with TXT records.  The string will be automatically decoded on
the client side.


ATTRIBUTE MAPPING


By default, attributes are represented by TXT resource records,
but certain attributes are instead represented by APL records (RFC
3123) as they are much more efficient at expressing permission lists.
The negative APL syntax is *NOT* supported.

Attributes that are represented by APL records:

 allow-query, allow-transfer, allow-notify, allow-recursion, masters,
  also-notify-list, default-forward-list, forward-list

And some intended for late-binding uses- these are up to you to give
meaning to and interpret:

 local-bridge, local0-apl, local1-apl, local2-apl


STANDARD ATTRIBUTE MEANINGS


*forward*: boolean indicating this zone should have queries forwarded
elsewhere.  This exists separately from *forward-list* in order to allow
evaluated expressions to signal true/false simply.

*forward-list*: list of IPs to forward the queries to.  The existence of
*forward-list* does not imply forwarding is happening EXCEPT in the
default case of the metazone itself; it's always forwarded.  So, 
the *forward* attribute is really "I want this forwarded and it's not a
metazone."

*members*: List of IPs of hosts that should consider themselves part of
a given NAME SERVER GROUP (NSG).  Any given DNS server can only be a member
of a single NSG.  NSG attributes override defaults.

*default-forward*: Is there a forward of last resort (for name spaces the
server isn't authoritativve for)?
*default-forward-list*: List of IPs to forward unknown name spaces to for
resolution.  This could be a set of public DNS proxies somewhere at the data
center edge.
*zone-list*: Applied at default and NSG levels, this is a list of zone lists
that should be included in the name server configuration (at default: all
servers) or (at NSG: for the members of the NSG)

