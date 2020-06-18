import socket
import json

from dnslib import RCODE, QTYPE, RR
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger
from odns import ODNSCypher
from urllib.request import Request, urlopen

ODNS_SUFFIX = ".odns"
DOH_SERVER = "cloudflare-dns.com"


class ODNSLocalProxy(BaseResolver):

    """
        ODNS Local Intercepting resolver

        Cyphers all requests received and forwards them to a recursive resolver
    """

    def __init__(self, upstream, skip):
        """
            upstream        - upstream DoH server
            skip            - list of wildcard labels to skip
        """
        self.upstream = upstream
        self.skip = skip
        self.crypto = ODNSCypher()
        self.server_pk = None

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype
        print("QNAME : ", qname)

        # Test if we skip the request
        if not any([qname.matchGlob(s) for s in self.skip]):
            # Cypher the query
            query = bytes(str(qname), encoding="utf-8")
            print("query: ", query)
            print("pk: ", self.server_pk)
            encrypted, aes_key = self.crypto.encrypt_query(
                query, self.server_pk)

            new_qname = encrypted.hex() + ODNS_SUFFIX
            print("Encrypted : ", new_qname)

            # Forward it to the upstream server
            try:
                json = query(new_qname, type=qtype, server=self.upstream)
                for entry in json["Answer"]:
                    # Decypher the reply
                    answer = self.crypto.decrypt_answer(entry["data"], aes_key)
                    reply.add_answer(
                        RR(entry["name"], QTYPE[entry["type"]], rdata=answer))
                    print("{} -> {}".format(qname, answer))
            except Exception as ex:
                print("Problem in the DOH resolution : {}".format(ex))
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

        # Else, just forward
        if not reply.rr:
            print("Query forwarded")
            try:
                json = query(new_qname, type=qtype, server=self.upstream)
                for entry in json["Answer"]:
                    # Decypher the reply
                    reply.add_answer(
                        RR(entry["name"], QTYPE[entry["type"]], rdata=entry["data"]))
            except socket.timeout:
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

        return reply

    def query(name, type='A', server=DOH_SERVER, path="/dns-query"):
        """
        Queries the server through the JSON interface
        Ref : https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/
        """

        # Send the request
        addr = "https://{}{}?name={}&type={}".format(server, path, name, type)
        req = Request(addr, headers={"Accept": "application/dns-json"})
        # Parse the answer
        content = urlopen(req).read().decode()
        return json.loads(content)


if __name__ == '__main__':

    import argparse
    import time

    p = argparse.ArgumentParser(description="ODNS Local Proxy")
    p.add_argument("--port", "-p", type=int, default=53,
                   metavar="<port>",
                   help="Local proxy port (default:53)")
    p.add_argument("--address", "-a", default="",
                   metavar="<address>",
                   help="Local proxy listen address (default:all)")
    p.add_argument("--upstream", "-u", default=DOH_SERVER,
                   metavar="<dns server:port>",
                   help="Upstream DoH server (default:{})".format(DOH_SERVER))
    p.add_argument("--skip", "-s", action="append",
                   metavar="<label>",
                   help="Don't intercept matching label (glob)")
    p.add_argument("--log", default="request,reply,truncated,error",
                   help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix", action='store_true', default=False,
                   help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()

    args.dns, _, args.dns_port = args.upstream.partition(':')
    args.dns_port = int(args.dns_port or 53)

    resolver = ODNSLocalProxy(args.upstream,
                              args.skip or [])
    logger = DNSLogger(args.log, args.log_prefix)

    print("Starting ODNS Local Poxy ({}:{} -> {})".format(
        args.address or "*", args.port,
        args.upstream))

    if resolver.skip:
        print("    Skipping:", ", ".join(resolver.skip))
    print()

    DNSHandler.log = {
        'log_request',      # DNS Request
        'log_reply',        # DNS Response
        'log_truncated',    # Truncated
        'log_error',        # Decoding error
    }

    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger)
    udp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)
