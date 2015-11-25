#!/usr/bin/env python
#
#The MIT License (MIT)
#
# Copyright (c) 2015 Bit9 + Carbon Black
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# -----------------------------------------------------------------------------

import sys
import optparse
import os
import pprint
import cbapi
import json
import shutil
from datetime import datetime

from jinja2 import Environment, FileSystemLoader
import redis_cbapi_wrapper as rcbapi

class IncidentReport(object):
    def __init__(self, url, token):
        self.cb = rcbapi.RedisCbApiWrapper(url, token)
        self.outdir = "EnvReport"

    def _output_from_template(self):
        THIS_DIR = os.path.dirname(os.path.abspath(__file__))
        TEMPLATE_FILE = "environment_report.html"

        template_vars = {"facets": self.facet}

        #pprint.pprint(self.facet)

        j2_env = Environment( loader=FileSystemLoader(THIS_DIR),
                              trim_blocks=True)
        self.htmlfile = file(self.outdir + "/index.html", 'wb')
        self.htmlfile.write( j2_env.get_template(TEMPLATE_FILE).render(template_vars).encode('utf-8'))

    def generate_report(self, param):
        try:
            os.makedirs(self.outdir)
        except:
            pass

        try:
            shutil.copyfile("default.png", self.outdir + "/default.png")
            shutil.copytree("css", self.outdir + "/css")
            shutil.copytree("fonts", self.outdir + "/fonts")
            shutil.copytree("js", self.outdir + "/js")
        except:
            pass

        self._output_from_template()

    def populate_top_hits(self, cb, time_range):
        results = cb.process_search(r"%s" % time_range, rows=0)

        facets = results.get('facets')

        total_processes = results.get('total_results')
        usernames = facets.get('username_full')
        hostnames = facets.get('hostname')
        process_names = facets.get('process_name')

        usernames = usernames[0:20]
        hostnames = hostnames[0:20]
        process_names = process_names[0:20]

        self.facet = {}
        self.facet['total_processes'] = total_processes
        self.facet['top_usernames'] = usernames
        self.facet['top_hostnames'] = hostnames
        self.facet['top_process_names'] = process_names

    def populate_java_hits(self, cb, time_range):
        hits = []
        results = cb.process_search(r"%s (process_name:java.exe or process_name:javaw.exe)" % time_range)
        facets = results.get('facets')
        process_md5s = facets.get('process_md5')
        for process_dict in process_md5s:
            process_md5 = process_dict.get('name')
            process_count = process_dict.get('value')
            try:
                result = cb.binary_summary(process_md5)
                hit = (result.get('product_version'), result.get('file_version'), process_count, result.get('host_count'), result.get('server_added_timestamp'), process_md5)
                hits.append(hit)
            except:
                pass
        hits = sorted(hits, key=lambda tup: tup[0])
        unique_versions = set([hit[0] for hit in hits])

        self.java = {}
        self.java['unique_count'] = unique_versions
        self.java['details'] = hits

        #pprint.pprint(self.java)

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Dump Binary Info")

    #
    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    time_range = "start:-24h"

    results = {}

    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    #results.update( populate_java_hits(cb, time_range) )
    #results.update( populate_top_hits(cb, time_range) )

    report = IncidentReport(cb.server, cb.token)
    report.populate_top_hits(cb, time_range)
    report.populate_java_hits(cb, time_range)
    report.generate_report("test")

    #pprint.pprint(results)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


