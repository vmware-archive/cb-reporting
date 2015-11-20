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

import redis_cbapi_wrapper as rcbapi
import pprint
import base64
import os
import time
import socket
import struct
import shutil
import sys
import optparse
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

cb_datetime_format = "%Y-%m-%d %H:%M:%S.%f"

class IncidentReport(object):
    def __init__(self, url, token):
        self.sensor = None
        self.htmlfile = None

        self.cb = rcbapi.RedisCbApiWrapper(url, token)


    def _write_iconfile(self, md5):
        if not md5:
            return
        binary_details = self.cb.binary_summary(md5)
        if not binary_details:
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
                         "childprocs": self.childProcs,
                         "netconns": self.netconns,
                         "filemods": self.filemods,
                         "regmods": self.regmods,
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

    def _parse_regmod(self, regmod):
        def _lookup_type(regmodtype):
            if regmodtype == 1:
                return 'CreatedKey'
            elif regmodtype == 2:
                return 'FirstWrote'
            elif regmodtype == 4:
                return 'DeletedKey'
            elif regmodtype == 8:
                return 'DeletedValue'

        parts = regmod.split('|')
        new_regmod = {}
        timestamp = datetime.strptime(parts[1], cb_datetime_format)
        new_regmod['timestamp'] = timestamp
        new_regmod['type'] = _lookup_type(int(parts[0]))
        new_regmod['path'] = parts[2]

        new_regmod['tamper_flag'] = False
        if len(parts) > 3 and parts[3] == 'true':
            new_regmod['tamper_flag'] = True
        return new_regmod

    def _parse_filemod(self, filemod):
        def _lookup_type(filemodtype):
            if filemodtype == 1:
                return 'CreatedFile'
            elif filemodtype == 2:
                return 'FirstWrote'
            elif filemodtype == 4:
                return 'Deleted'
            elif filemodtype == 8:
                return 'LastWrote'

        def _lookup_filetype(filetype):
            if filetype == 1:
                return 'PE'
            elif filetype == 2:
                return 'ELF'
            elif filetype == 3:
                return 'MachO'
            elif filetype == 8:
                return 'EICAR'
            elif filetype == 0x10:
                return 'DOC'
            elif filetype == 0x11:
                return 'DOCX'
            elif filetype == 0x30:
                return 'PDF'
            elif filetype == 0x40:
                return 'ZIP'
            elif filetype == 0x41:
                return 'LZH'
            elif filetype == 0x42:
                return 'LZW'
            elif filetype == 0x43:
                return 'RAR'
            elif filetype == 0x44:
                return 'TAR'
            elif filetype == 0x45:
                return '7Z'
            else:
                return 'Unknown'

        if not filemod:
            return

        parts = filemod.split('|')
        new_file = {}
        new_file['type'] = _lookup_type(int(parts[0]))
        timestamp = datetime.strptime(parts[1], cb_datetime_format)
        new_file['timestamp'] = timestamp
        new_file['path'] = parts[2]
        new_file['md5'] = parts[3]
        new_file['filetype'] = 'Unknown'
        if len(parts) > 4 and parts[4] != '':
            new_file['filetype'] = _lookup_filetype(int(parts[4]))

        new_file['tamper_flag'] = False
        if len(parts) > 5 and parts[5] == 'true':
            new_file['tamper_flag'] = True

        return new_file

    def _parse_netconn(self, netconn):
        parts = netconn.split('|')
        new_conn = {}
        timestamp = datetime.strptime(parts[0], cb_datetime_format)
        new_conn['timestamp'] = timestamp
        try:
            new_conn['ipaddr'] = socket.inet_ntop(socket.AF_INET, struct.pack('>i', int(parts[1])))
        except:
            new_conn['ipaddr'] = "0.0.0.0"
        new_conn['port'] = int(parts[2])
        new_conn['dns'] = parts[4]
        if parts[5] == 'true':
            new_conn['direction'] = 'Outbound'
        else:
            new_conn['direction'] = 'Inbound'
        return new_conn

    def _parse_childproc(self, childproc):
        parts = childproc.split('|')
        timestamp = datetime.strptime(parts[0], cb_datetime_format)
        new_childproc = {}
        new_childproc['procguid'] = parts[1][0:len(parts[1])-9]
        new_childproc['md5'] = parts[2]
        new_childproc['path'] = parts[3]
        new_childproc['pid'] = parts[4]

        new_childproc['terminated'] = False
        if parts[5] == 'true':
            new_childproc['terminated'] = True

        new_childproc['tamper_flag'] = False
        if len(parts) > 6 and parts[6] == 'true':
            new_childproc['tamper_flag'] = True
        return new_childproc

    def getFileMods(self, process_guid):
        filemodlist = []
        filemods = self.cb.process_events(self.process.get('id'), 1).get('process').get('filemod_complete')
        if filemods:
            for filemod in filemods:
                filemod = self._parse_filemod(filemod)
                filemodlist.append(filemod)
        return filemodlist

    def getChildProcs(self, starting_guid):
        childproclist = []

        childProcs = self.cb.process_events(self.process.get('id'), 1).get('process').get('childproc_complete')
        if childProcs:
            for childProc in childProcs:
                childProc = self._parse_childproc(childProc)
                child_process = self.cb.process_summary(childProc['procguid'], 1).get('process', {})
                if child_process:
                    childproclist.append(child_process)
        return childproclist

    def getNetConns(self, process_guid):
        netconnslist = []

        events = self.cb.process_events(self.process.get('id'), 1).get('process')
        if "netconn_complete" in events:
            netconn_events = events.get('netconn_complete')
            for netconn in netconn_events:
                netconn = self._parse_netconn(netconn)
                netconnslist.append(netconn)
        return netconnslist

    def getRegMods(self, process_guid):
        regmodslist = []

        events = self.cb.process_events(self.process.get('id'), 1).get('process')
        if "regmod_complete" in events:
            regmods = events.get('regmod_complete')
            for regmod in regmods:
                regmod = self._parse_regmod(regmod)
                regmodslist.append(regmod)
        return regmodslist

    def generate_report(self, starting_guid):
        self.outdir = starting_guid

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
            print "Error Copying support files to output directory"
            print "Files might already exist"

        self.process = self.cb.process_summary(starting_guid, 1).get('process', {})
        self.sensor = self.cb.sensor(self.process.get('sensor_id'))

        process_path = self.process.get('path')
        process_md5 = self.process.get('process_md5')
        hostname = self.process.get('hostname')

        self.process['id'] = starting_guid

        #
        # get execution tree
        #
        self.executors = [self.process]
        self.walk_executors_up(self.process.get('parent_unique_id'),
                               self.executors)
        for executor in self.executors:
            self._write_iconfile(executor.get('process_md5'))

        #
        # Get all child procs
        #
        self.childProcs = self.getChildProcs(self.process.get('parent_unique_id'))
        for childproc in self.childProcs:
            self._write_iconfile(childproc.get('process_md5'))

        #
        # Get File Mods
        #
        self.filemods = self.getFileMods(self.process.get('parent_unique_id'))

        #
        # Get Reg Mods
        #
        self.regmods = self.getRegMods(self.process.get('parent_unique_id'))

        #
        # get writers
        #
        self.writers = []
        self.walk_writers_by_path(hostname, process_path, self.writers)
        for writer in self.writers:
            self._write_iconfile(writer.get('process_md5'))

        #
        # Write our own icon
        #
        if process_md5 in self.process:
            self._write_iconfile(self.process['process_md5'])

        self.netconns = self.getNetConns(self.process.get('parent_unique_id'))

        #self._report_to_html(starting_guid)
        self._output_from_template(starting_guid)
        return

    def walk_executors_up(self, parent_guid, executors, depth = 3):
        if depth == 0:
            return
        parent_guid = str(parent_guid)[0:len(parent_guid)-9]
        parent_process = self.cb.process_summary(parent_guid, 1).get('process', {})
        if 'process_name' not in parent_process:
            parent_process['process_name'] = "Unknown"

        executors.insert(0, parent_process)
        if 'process_md5' in parent_process:
            self._write_iconfile(parent_process['process_md5'])

        path = parent_process.get('path')
        if not path or "explorer.exe" in path or "services.exe" in path:
            return

        parent_guid = parent_process.get('parent_unique_id')
        if parent_guid:
            self.walk_executors_up(parent_guid, executors, depth - 1)

    def walk_writers_by_path(self, hostname, process_path, writers, depth = 1):
        if depth == 0:
            return

        writer_processes = self.cb.process_search(
            "filemod:\"%s\" hostname:%s" % (process_path, hostname),
            facet_enable=False).get('results', [])

        for writer in writer_processes:
            writer_path = writer.get('path')
            writers.insert(0, writer)
            self.walk_writers_by_path(hostname, writer_path, writers, depth - 1)


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
    parser.add_option("-g", "--guid", action="store", default=None, dest="guid",
                      help="Generate a report for this GUID\nExample: -g 00000004-0000-09a8-01d0-ceebd9b41fbc")
    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token or not opts.guid:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    rep = IncidentReport(opts.url, opts.token)
    rep.generate_report(opts.guid)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))



