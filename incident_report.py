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
#
#  last updated 2015-11-16 by Jason McFarland jmcfarland@bit9.com
#

__author__ = 'jmcfarland'

import cbapi.util.redis_cbapi_wrapper as rcbapi
import pprint
import base64
import os
import time
from jinja2 import Environment, FileSystemLoader
from yattag import Doc, indent

class IncidentReport(object):
    def __init__(self, url, token):
        self.sensor = None
        self.cb = rcbapi.RedisCbApiWrapper(url, token)
        self.outdir = "reports"
        try:
            os.makedirs(self.outdir)
        except:
            pass

        self.htmlfile = None

    def _write_iconfile(self, md5):
        binary_details = self.cb.binary_summary(md5)
        if not binary_details:
            #
            # Write a generic icon
            #
            return

        self.iconfile = file(self.outdir + ("/%s.png" % md5), 'wb')
        self.iconfile.write(base64.b64decode(binary_details.get('icon')))
        self.iconfile.close()

    def _get_binary_info(self, md5):
        binary_details = self.cb.binary_summary(md5)
        if not binary_details:
            binary_details = {}
        sigstatus = binary_details.get('digsig_result', '(unknown)')
        version = binary_details.get('product_version', '(unknown)')
        company_name = binary_details.get('company_name', '(unknown)')
        publisher = binary_details.get('publisher', '(unknown)')

        return "%s - %s - %s - %s - %s" % (md5, sigstatus, version, company_name, publisher)

    def _get_process_frequency(self, process_md5):
        process_count = self.cb.process_search("process_md5:%s" % process_md5, start=0, rows=0, facet_enable=False)
        host_count = self.cb.host_count(process_md5)
        return process_count, host_count

    def _output_from_template(self, starting_guid):
        THIS_DIR = os.path.dirname(os.path.abspath(__file__))
        TEMPLATE_FILE = "incident_report.html"

        process_md5 = self.process.get('process_md5')
        process_count, host_count = self._get_process_frequency(process_md5)

        template_vars = {"process": self.process,
                         "process_md5": process_md5,
                         "process_count": process_count,
                         "host_count": host_count,
                         "starting_guid": starting_guid,
                         "writers": self.writers,
                         "executors": self.executors,
                         "report": self}

        j2_env = Environment( loader=FileSystemLoader(THIS_DIR),
                              trim_blocks=True)

        if not self.htmlfile:
            self.htmlfile = file(self.outdir + ("/%s.html" % starting_guid), 'wb')
            self.htmlfile.write( j2_env.get_template(TEMPLATE_FILE).render(template_vars))

    def _report_to_html(self, starting_guid):
        if not self.htmlfile:
            self.htmlfile = file(self.outdir + ("/%s.html" % starting_guid), 'wb')

        process_md5 = self.process.get('process_md5')
        process_count, host_count = self._get_process_frequency(process_md5)

        doc, tag, text = Doc().tagtext()

        doc.asis('<!DOCTYPE html>')
        with tag('html'):
            with tag('head'):
                with tag('title'):
                    text("Incident Report for %s on %s" % (self.process.get('process_name'),
                                                           self.process.get('hostname')))
                doc.asis("""<link rel="stylesheet" type="text/css" href="../bootstrap.min.css">""")
                doc.asis("""<link rel="stylesheet" type="text/css" href="../bootstrap-theme.min.css">""")
            with tag('body'):
                with tag('div', klass='container'):
                    with tag('div', klass="container-fluid"):
                        with tag('div', klass="row"):
                            with tag('h2'):
                                text("Incident Summary: ")
                                self._write_iconfile(process_md5)
                                doc.stag('img', src="%s.png" % process_md5)
                                text(" '%s' on %s" % (self.process.get('process_name'),
                                                    self.process.get('hostname')))

                            with tag('h3'):
                                text("%s" % process_md5)

                        with tag('div', klass="row"):
                            text("Executed at %s by %s" % (self.process.get('start'),
                                                           self.process.get('username')))
                        with tag('div', klass="row"):
                            text("Process seen %d times and seen on %d hosts" % (process_count.get('total_results'),
                                                                                 host_count.get('hostCount')))

                        doc.stag('hr')

                        with tag('h3'):
                            text("Writer Tree")

                        for index, writer in enumerate(self.writers):
                            with tag('div', id="writer-%d" % index):
                                self._write_iconfile(writer.get('process_md5'))
                                doc.stag('img', width="32", src="%s.png" % writer.get('process_md5'))

                                with tag('strong'):
                                    text(" %s " % (writer.get('process_name')))
                                text("-> %s" % (writer.get('path')))
                                doc.stag('br')
                                text("(%s)" % writer.get('cmdline'))
                                doc.stag('br')
                                text("(%s)" % writer.get('id'))
                                doc.stag('br')
                                text(self._get_binary_info(writer.get('process_md5')))
                                doc.stag('br')
                                process_count, host_count = self._get_process_frequency(writer.get('process_md5'))
                                text("Process seen %d times and seen on %d hosts" % (process_count.get('total_results'),
                                                                                     host_count.get('hostCount')))
                                doc.stag('br')
                                doc.stag('br')

                        doc.stag('hr')

                        with tag('div', klass="row"):
                            with tag('h3'):
                                text("Execution Tree")

                            margin_size = 0
                            for executor in self.executors:
                                with tag('div', style="margin-left:%dpx; width:100%%;" % margin_size):
                                    margin_size += 30
                                    self._write_iconfile(executor.get('process_md5'))
                                    doc.stag('img', width="32", src="%s.png" % executor.get('process_md5'))

                                    with tag('strong'):
                                        text(" %s" % executor.get('process_name'))
                                    text("-> %s" % (executor.get('path')))
                                    doc.stag('br')
                                    text("(%s)" % executor.get('cmdline'))
                                    doc.stag('br')
                                    text(self._get_binary_info(executor.get('process_md5')))
                                    doc.stag('br')
                                    process_count, host_count = self._get_process_frequency(executor.get('process_md5'))
                                    text("Process seen %d times and seen on %d hosts" % (process_count.get('total_results'),
                                                                                         host_count.get('hostCount')))
                                    doc.stag('br')
                                    doc.stag('br')

                        doc.stag('hr')

                        with tag('div', klass="row"):
                            with tag('h3'):
                                text("Root Cause")

                            writer = self.writers[0]
                            written_path = self.writers[1].get('path')
                            writer_events = self.cb.process_events(writer.get('id'), 1).get('process')
                            filemod_completes = writer_events.get('filemod_complete', [])
                            netconn_completes = writer_events.get('netconn_complete', [])
                            write_timestamp = None
                            for filemod_complete in filemod_completes:
                                fields = filemod_complete.split("|")
                                if fields[0] == "1" and fields[2] == written_path:
                                    write_timestamp = fields[1]
                                    break
                            if write_timestamp:

                                potential_netconns = []
                                for netconn_complete in netconn_completes:
                                    fields = netconn_complete.split("|")
                                    if fields[0] <= write_timestamp:
                                        potential_netconns.append(fields)
                                    else:
                                        break
                                for potential_netconn in potential_netconns:
                                    # TODO -- cleaner netconn stuff
                                    domain = potential_netconn[4]
                                    if domain:
                                        resp = self.cb.process_search("domain:%s" % domain, start=0, rows=0, facet_enable=False)
                                        total_results = resp.get('total_results')
                                        if total_results < 1000:
                                            text("%s => %s:%s (%d)" % ( potential_netconn[0],
                                                                        potential_netconn[4],
                                                                        potential_netconn[2],
                                                                        total_results))
                                            doc.stag("br")
                                with tag('strong'):
                                    text("%s => %s wrote %s" % (write_timestamp, writer.get('process_name'), written_path))
                                doc.stag("br")

                    doc.stag('br')
                    doc.stag('br')
                    doc.stag('br')

        self.htmlfile.write(indent(doc.getvalue()))


    def generate_report(self, starting_guid):

        self.process = self.cb.process_summary(starting_guid, 1).get('process', {})
        self.sensor = self.cb.sensor(self.process.get('sensor_id'))

        process_path = self.process.get('path')
        process_md5 = self.process.get('process_md5')
        hostname = self.process.get('hostname')

        self.process['id'] = starting_guid

        # get execution tree
        self.executors = [self.process]
        self.walk_executors_up(self.process.get('parent_unique_id'), self.executors)

        # TODO -- walk_executors_down

        # get writer tree
        self.writers = [self.process]
        self.walk_writers_by_path(hostname, process_path, self.writers)

        #self._report_to_html(starting_guid)
        self._output_from_template(starting_guid)
        return

    def walk_executors_up(self, parent_guid, executors, depth = 3):
        if depth == 0:
            return
        parent_guid = str(parent_guid)[0:len(parent_guid)-9]
        parent_process = self.cb.process_summary(parent_guid, 1).get('process', {})

        executors.insert(0, parent_process)

        path = parent_process.get('path')
        if not path or "explorer.exe" in path or "services.exe" in path:
            return

        parent_guid = parent_process.get('parent_unique_id')
        if parent_guid:
            self.walk_executors_up(parent_guid, executors, depth - 1)

    def walk_writers_by_path(self, hostname, process_path, writers, depth = 3):
        if depth == 0:
            return
        writer_processes = self.cb.process_search(
            "filemod:\"%s\" hostname:%s" % (process_path, hostname),
            facet_enable=False).get('results', [])

        for writer in writer_processes:
            writer_path = writer.get('path')
            writers.insert(0, writer)

            if "chrome.exe" in writer_path:
                break
            if "outlook.exe" in writer_path:
                break
            if "iexplore.exe" in writer_path:
                break
            if "firefox.exe" in writer_path:
                break
            self.walk_writers_by_path(hostname, writer_path, writers, depth - 1)

if __name__ == "__main__":
    rep = IncidentReport(url, token)
    starting_guid = "00000008-0000-0174-01d1-2188fcffee7a"
    #starting_guid = "00000004-0000-09a8-01d0-ceebd9b41fbc"
    rep.generate_report(starting_guid)


