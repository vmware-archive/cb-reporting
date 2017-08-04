#!/usr/bin/env python
import os
import shutil
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from cbapi.response import Process, Binary, Feed
from cbapi import errors
import cbapi.example_helpers as cbhelper

#
# The MIT License (MIT)
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
#  updated 7/2017 by Zachary Estep, cbapi-1.2 support
#

__author__ = 'jmcfarland+zestep'


def write_iconfile(output_directory, process=None):
    try:
        if process and process.binary and process.binary.md5:
            if process.binary.icon:
                write_file(output_directory, process.binary.md5, ".png", process.binary.icon)
            else:
                dest = os.path.join(output_directory, process.binary.md5 + ".png")
                src = os.path.join(output_directory, "images", "default.png")
                shutil.copy(src, dest)
        else:
            pass
    except:
        pass



'''helper method to write a file'''


def write_file(path, name, ext, contents=None):
    if not path or not name or not ext or not contents:
        return
    dest = os.path.join(path, name + ext)
    f = file(dest, 'wb')
    f.write(contents)
    f.close()


'''copy static files from 'css','fonts','js','images' '''


def copy_static_files(output_directory):
    dirs_to_copy = ["css", "fonts", "js", "images"]
    for d in dirs_to_copy:
        from_dir = os.path.join(".", d)
        to_dir = os.path.join(".", output_directory, d)
        try:
            shutil.copytree(from_dir, to_dir)
        except OSError:
            pass


''' output the report using a jinga2 template'''


def output_report_from_template(cbserver, output_directory, process, writers=None,
                                feed_hits=None, hostnames=None, filepaths=None, parents=None):
    template_vars = {"process": process,
                     "sensor": process.sensor,
                     "writers": writers if writers else [],
                     "children": [child for child in process.children],
                     "parents": [parent for parent in parents ] if parents else [],
                     "modloads": [modload for modload in process.modloads],
                     "netconns": [nc for nc in process.netconns],
                     "regmods": [rm for rm in process.regmods],
                     "crossprocs": [cp for cp in process.crossprocs],
                     "binary": process.binary,
                     "feed_hits": feed_hits if feed_hits else [],
                     "time_generated": datetime.now(),
                     "cbserver": cbserver,
                     "hostnames": hostnames if hostnames else [],
                     "filepaths": filepaths if filepaths else []}

    j2_env = Environment(loader=FileSystemLoader("."),
                         trim_blocks=True)

    report_htmlfile = file(os.path.join(output_directory, "index.html"), 'wb')
    report_htmlfile.write(j2_env.get_template("incident_report.j2").render(template_vars).encode("UTF-8"))


class IncidentReportGenerator(object):

    def __init__(self, cbapi):
        self.cb = cbapi

    '''generate an incident report about a target guid, optional verbose console output'''
    def generate_report(self, guid, verbose=False):

        #build the report directory path and lookup the target process by GUID
        output_directory = os.path.join("reports", guid)
        process = self.cb.select(Process, guid)

        if verbose:
            #optionally print the process and binary information to console
            process.refresh()
            process.binary.refresh()
            print(process)
            print(process.binary)

        #makedirs will attempt to create the ./reports/{guid} directory
        if process.binary is not None:
            try:
                os.makedirs(output_directory)
            except OSError:
                pass
        else:
            return

        # copy the static resources (images,css,js,etc) to the ./reports/{guid} directory
        copy_static_files(output_directory)

        # write the icon file for the target process
        write_iconfile(output_directory, process)

        # walk children of the target process and write icons
        for child in process.children:
            write_iconfile(output_directory, child.process)

        # find processes that have written to the target process's binary
        writers = []
        writers.extend(self.cb.select(Process).where("filemod:{} and hostname:{} and process_md5:*"
                                                     .format(process.path, process.hostname)))
        # and write icon files for the writers
        for writer in writers:
            write_iconfile(output_directory, writer)

        # build a list of hostname/filepath facets for this process-binary-by-md5
        facets = self.cb.select(Process).where("process_md5:" + process.process_md5).facets()
        filepaths = [{"filepath": e['name'], "percentage": e['ratio']} for e in facets.get('path_full')]
        hostnames = [{'hostname': e['name'], 'percentage': e['ratio']} for e in facets.get('hostname')]

        # process alliance threat intelligence feed hits + write icons for feeds
        feed_hits = []
        # Todo : provide link to relevant threat report
        for feed_name in process.tags:
            # A Process has fields like "alliance_score_tor,alliance_data_tor" for each
            alliance_score_n = "alliance_score_{}".format(feed_name)
            alliance_data_n = "alliance_data_{}".format(feed_name)
            feed = self.cb.select(Feed).where("name:" + feed_name).first()
            write_file(output_directory, feed.name, ".png", feed.icon_small)
            feed_hits.append({"feed": feed.name,
                              "url": feed.provider_url,
                              "score": getattr(process, alliance_score_n),
                              "data": getattr(process, alliance_data_n)})

        # walk execution tree/parents and write icons
        for parent in process.parents:
            write_iconfile(output_directory, parent)

        # use jinga templating engine to generate a report as html
        output_report_from_template(self.cb.url, output_directory, process, writers, feed_hits, hostnames, filepaths)

        print("[+] Report generated in ./{}\n".format(output_directory + "/"))


def main():
    parser = cbhelper.build_cli_parser()
    parser.add_argument("--guid", dest="guid", help="GUID of target process",required=True)
    args = parser.parse_args()
    cbapi = cbhelper.get_cb_response_object(args)
    repgen = IncidentReportGenerator(cbapi=cbapi)
    print("[+] Generating report for process guid: {}\n".format(args.guid))
    repgen.generate_report(guid=args.guid, verbose=True if args.verbose else False)

if __name__ == "__main__":
    main()
