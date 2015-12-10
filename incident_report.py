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
from progress.bar import Bar

toolbar_width = 40
cb_datetime_format = "%Y-%m-%d %H:%M:%S.%f"
#
# Progress Bar
#
bar = Bar('Generating', max=10)

class IncidentReport(object):
    def __init__(self, url, token):
        self.sensor = None
        self.htmlfile = None
        self.cbserver = url

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

    def _get_process_count(self, process_md5):
        return self.cb.process_search("process_md5:%s" % process_md5, start=0, rows=0, facet_enable=False)

    def _get_process_host_count(self, process_md5):
        return self.cb.host_count(process_md5)

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
                         "binary" : self.binary,
                         "feed_hits" : self.feed_hits,
                         "time_generated": self.time_generated,
                         "cbserver": self.cbserver,
                         "hostnames": self.hostnames,
                         "filepaths": self.filepaths,
                         "report": self}

        j2_env = Environment( loader=FileSystemLoader(THIS_DIR),
                              trim_blocks=True)

        if not self.htmlfile:
            self.htmlfile = file(self.outdir + "/index.html", 'wb')
            self.htmlfile.write( j2_env.get_template(TEMPLATE_FILE).render(template_vars).encode('utf-8'))

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
                if childProc['terminated']:
                    #
                    # We don't want to double count child procs
                    #
                    continue
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

    def getFacetsByMd5(self, md5):
        data = self.cb.process_search("md5:"+md5, rows=1, start=0).get('facets',{})

        self.filepaths = []
        for elem in data.get('path_full',[]):
            facet = {}
            facet['filepath'] = elem['name']
            facet['percentage'] = elem['ratio']
            self.filepaths.append(facet)

        self.hostnames = []
        for elem in data.get('hostname',[]):
            facet = {}
            facet['hostname'] = elem['name']
            facet['percentage'] = elem['ratio']
            self.hostnames.append(facet)


    def generate_report(self, starting_guid):
        global bar
        self.time_generated = datetime.now()
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
            pass
        bar.next()

        self.process = self.cb.process_summary(starting_guid, 1).get('process', {})
        bar.next()

        #
        # Get Feed hits
        #
        self.feed_hits = []

        self.process_events = self.cb.process_events(starting_guid, 1).get('process', {})

        if 'alliance_hits' in self.process_events:
            for key, value in self.process_events['alliance_hits'].iteritems():
                tempdict = {}
                tempdict['display_name'] = value['feedinfo']['display_name']
                tempdict['summary'] = value['feedinfo']['summary']
                tempdict['number_of_hits'] = len(value['hits'])
                self.feed_hits.append(tempdict)

        self.binary = self.cb.binary_summary(self.process.get('process_md5'))
        bar.next()

        self.sensor = self.cb.sensor(self.process.get('sensor_id'))
        bar.next()

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
        bar.next()

        self.walk_executors_down(self.process['unique_id'], self.executors)

        #
        # Get all child procs
        #
        self.childProcs = self.getChildProcs(self.process.get('parent_unique_id'))
        for childproc in self.childProcs:
            self._write_iconfile(childproc.get('process_md5'))
        bar.next()

        #
        # Get File Mods
        #
        self.filemods = self.getFileMods(self.process.get('parent_unique_id'))
        bar.next()

        #
        # Get Reg Mods
        #
        self.regmods = self.getRegMods(self.process.get('parent_unique_id'))
        bar.next()

        #
        # get writers
        #
        self.writers = [self.process]
        self.walk_writers_by_path(hostname, process_path, self.writers)
        for writer in self.writers:
            self._write_iconfile(writer.get('process_md5'))
        bar.next()

        #
        # Write our own icon
        #
        if process_md5 in self.process:
            self._write_iconfile(self.process['process_md5'])

        self.netconns = self.getNetConns(self.process.get('parent_unique_id'))

        self.getFacetsByMd5(self.process['process_md5'])

        self._output_from_template(starting_guid)
        bar.next()

        bar.finish()
        return

    def walk_executors_down(self, process_guid, executors, depth = 5):
        if depth == 0:
            return
        try:
            process_guid = str(process_guid)[0:len(process_guid)-9]
        except:
            pass

        start_time = None
        currentCandidate = None

        process_summary = self.cb.process_summary(process_guid,1)
        for child in process_summary['children']:
            if not currentCandidate or start_time < child['start']:
                currentCandidate = child

        if currentCandidate:
            executors.append(child)
            self.walk_executors_down(child['unique_id'], executors, depth - 1)


    def walk_executors_up(self, parent_guid, executors, depth = 5):
        if depth == 0:
            return
        try:
            parent_guid = str(parent_guid)[0:len(parent_guid)-9]
        except:
            pass
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

    def walk_writers_by_path(self, hostname, process_path, writers, depth = 5):
        if depth == 0:
            return

        writer_processes = self.cb.process_search(
            "filemod:\"%s\" hostname:%s" % (process_path, hostname),
            facet_enable=False).get('results', [])

        currentCandidate = None

        for writer in writer_processes:

            fileModEvents = self.cb.process_events(writer.get('id'), 1).get('process',{}).get('filemod_complete',[])

            for filemod in fileModEvents:
                filemod = self._parse_filemod(filemod)
                if filemod['path'] == process_path and filemod['type'] == "LastWrote":
                    if not currentCandidate or filemod['timestamp'] > currentCandidate['filemod']['timestamp']:
                        currentCandidate = {'process': writer, 'filemod': filemod}

        if currentCandidate:
            writers.insert(0, currentCandidate['process'])
            self.walk_writers_by_path(hostname, currentCandidate['process']['path'], writers, depth - 1)


def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]",
                                   description="Generates an Incident Report given a process guid")
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
        parser.print_help()
        sys.exit(-1)

    rep = IncidentReport(opts.url, opts.token)
    print "[+] Generating report for process guid: %s" % opts.guid
    rep.generate_report(opts.guid)
    print "[+] Report generated in ./%s" % rep.outdir + "/"

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))



