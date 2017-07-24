#!/usr/bin/env python
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

import os
import shutil
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from cbapi.response import *
import cbapi.example_helpers as cbhelper

''' helper method to write the icon for a binary '''


def write_iconfile(outdir, binary=None):
    if binary and binary.icon:
        write_file(outdir, binary.md5, ".png", binary.icon)
    else:
        dest = os.path.join(outdir, binary.md5 + ".png")
        src = os.path.join(outdir, "images", "default.png")
        shutil.copy(src, dest)
        

'''helper method to write a file'''

def write_file(path, name, ext, contents=None):
    if not (path) or not (name) or not (ext) or not(contents):
            return
    dest = os.path.join(path, name + ext)
    f = file(dest, 'wb')
    f.write(contents)
    f.close()

'''copy static files from 'css','fonts','js','images' '''


def copyStaticFiles(thedir ):
    # append ./ to the directory unless it is already relative to the cwd
    dirs_to_copy = ["css", "fonts", "js", "images"]
    for d in dirs_to_copy:
        fromdir = "./"+d
        todir = "./"+thedir+"/"+d
        try:
            shutil.copytree(fromdir,todir)
        except:
            pass
        
''' output the report using a jinga2 template'''

        
def output_from_template(cbserver, outdir, process, writers=None,
                             feed_hits=None, hostnames=None, filepaths=None):

    template_vars = {"process": process,
                     "sensor": process.sensor,
                     "writers": writers if writers else [],
                     "children": [child for child in process.children],
                     "parents": [parent for parent in process.parents],
                     "modloads": [modload for modload in process.modloads],
                     "netconns": [nc for nc in process.netconns],
                     "regmods": [rm for rm in process.regmods],
                     "crossprocs": [cp for cp in process.crossprocs],
                     "binary" : process.binary,
                     "feed_hits" : feed_hits if feed_hits else [],
                     "time_generated": datetime.now(),
                     "cbserver":  cbserver,
                     "hostnames": hostnames if hostnames else [],
                     "filepaths": filepaths if filepaths else [] }

    j2_env = Environment(loader=FileSystemLoader("."),
                              trim_blocks=True)

    htmlfile = file(outdir+"/index.html", 'wb')
    htmlfile.write( j2_env.get_template("incident_report.j2").render(template_vars).encode("UTF-8"))
 
class IncidentReportGenerator(object):
    
    #constructor, DI the cbresponse api bindings object
    def __init__(self, cbapi):
        self.cb =  cbapi
   
    #generate a report from a target GUID
    def generate_report(self, report_guid, verbose=False):
        outdir="reports/"+report_guid
        process = self.cb.select(Process, report_guid)
        
        if (verbose):
            process.refresh()
            process.binary.refresh()
            print(process)
            print(process.binary)

        if (process.binary is not None):
            try:
                os.makedirs(outdir)
            except:
                pass
        else:
            return
        
        #copy the static resources (images,css,js,etc) to the report directory
        copyStaticFiles(outdir)

        #write our own icon
        write_iconfile(outdir, process.binary)
        
        #walk children and write icons
        for child in process.children:
            write_iconfile(outdir,child.process.binary)

        #find processes that have written to the target process's binary
        writers = []
        writers.extend(self.cb.select(Process).where("filemod:{} hostname:{}"
                                                                .format(process.path, process.hostname)))
        #and write icon files for the writers
        for writer in writers:
            write_iconfile(outdir,writer.binary)

        #build a list of hostname/filepath facets for this process-binary-by-md5
        facets = self.cb.select(Process).where("process_md5:" + process.process_md5).facets()
        filepaths = [{"filepath": e['name'], "percentage": e['ratio']} for e in facets.get('path_full')]
        hostnames = [{'hostname': e['name'], 'percentage': e['ratio']} for e in facets.get('hostname')]

        # process alliance thread intelligence feed hits + write icons for feeds
        feed_hits = []
        # ToDO : provide link to relevant threat report
        for fn in process.tags:
                alliance_score_n = "alliance_score_{}".format(fn)
                alliance_data_n = "alliance_data_{}".format(fn)
                feed = self.cb.select(Feed).where("name:"+fn).first()
                write_file(outdir, feed.name, ".png", feed.icon_small)
                feed_hits.append({"feed": feed.name,
                                  "url": feed.provider_url,
                                  "score": getattr(process, alliance_score_n),
                                  "data": getattr(process, alliance_data_n)})
        
        #walk execution tree/parents and write icons
        for parent in process.parents:
            write_iconfile(outdir,parent.binary)
            
        #use jinga templating engine to generate a report as html
        output_from_template(self.cb.url, outdir, process, writers, feed_hits, hostnames, filepaths)
        
        print ("[+] Report generated in ./{}\n".format(outdir + "/"))
        

def main():
    parser = cbhelper.build_cli_parser()
    parser.add_argument("--guid", dest="guid", help="GUID of target process", required=True)
    args = parser.parse_args() 
    repgen = IncidentReportGenerator(cbapi=cbhelper.get_cb_response_object(args))
    print ("[+] Generating report for process guid: {}\n".format(args.guid))
    repgen.generate_report(args.guid,True if args.verbose else False )
    

if __name__ == "__main__":
    main()



