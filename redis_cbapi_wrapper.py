#!/usr/bin/env python

"""
Wrapper that caches cbapi results in redis.
"""
import traceback
import time
import requests

import cbapi
import redis
import simplejson

class RedisCbApiWrapper(object):
    """
    You need to have redis running before using this.

    Usually I run it as a daemon.
    """
    def __init__(self, cburl, token, redis_host='localhost', redis_port=6379):
        self._cburl = cburl
        self._token = token
        self._rclient = redis.StrictRedis(host=redis_host, port=redis_port, db=0, socket_timeout=2)
        self._cbapi = None

    def _cb(self):
        if not self._cbapi:
            self._cbapi = cbapi.CbApi(self._cburl, token=self._token, ssl_verify=False)

        #traceback.print_stack()
        # Take this out if you want ... just helps me realize when I am going remote for the data versus local in redis.
        #print "Using remote!"
        return self._cbapi

    def _get_redis(self, key):
        try:
            val = self._rclient.get(key)
            if val:
                return simplejson.loads(val)
        except Exception as e:
            return None
        else:
            return None

    def _set_redis(self, key, value):
        try:
            if type(value) != str:
                return self._rclient.set(key, simplejson.dumps(value))
            else:
                return self._rclient.set(key, value)
        except Exception as e:
            return None
        else:
            return None


    def get_processes_from_solr(self, args):
        """
        This is hit when I have searches that aren't available via our API but ARE available via SOLR.  Sometimes it
        might be that we don't return the right fields.

        Note that it expects to connect locally on 8080, so sometimes I have to setup a SSH tunnel.
        """
        key = "query-" + str(args)
        data = self._get_redis(key)
        if not data:
            response = requests.get('http://127.0.0.1:8080/solr/cbevents/select', params=args)
            data = response.json()
            self._set_redis(key, data)
        return data.get('response', {}).get('docs', [])

    def _frequency(self, frequency_type, frequency_value, process_name=None):
        key = "freq-%s-%s-%s" % (frequency_type, frequency_value, process_name or "")
        freq = self._get_redis(key)
        if freq:
            return freq
        start = time.time()
        freq = self._cb().frequency(frequency_type, frequency_value, process_name)
        end = time.time()
        print "Took %f seconds" % (end - start)
        self._set_redis(key, freq)
        return freq

    def frequency_ip(self, ipaddr_as_long, process_name=None):
        s = str(ipaddr_as_long)
        return self._frequency('ipaddr', s, process_name)

    def frequency_domain(self, domain, process_name=None):
        s = str(domain)
        return self._frequency('domain', s, process_name)

    def frequency_md5(self, md5, process_name=None):
        s = str(md5).lower()
        return self._frequency('md5', s, process_name)

    def frequency_filemod(self, path, process_name=None):
        s = str(path)
        return self._frequency('filemod', s, process_name)

    def frequency_regmod(self, path, process_name=None):
        s = str(path)
        return self._frequency('regmod', s, process_name)

    def frequency_modload(self, md5, process_name=None):
        s = str(md5)
        return self._frequency('modload', s, process_name)

    def events(self, process_id):
        events = self._get_redis("events-%s" % process_id)
        if events:
            return events

        events = self._cb().events(process_id, 1).get('process', {})
        if not events:
            events = self._cb().events(process_id, 0).get('process', {})

        self._set_redis("events-%s" % process_id, events)
        return events

    def host_count(self, md5):

        binary = self._get_redis("binary-%s" % md5)
        if not binary:
            binary = self._cb().binary_search("md5:%s" % md5)
        if not binary or "results" not in binary or len(binary["results"]) == 0:
            return {"hostCount": 0}
        numHosts = binary["results"][0]["host_count"]

        self._set_redis("binary-%s" % md5, binary)

        return  {"hostCount": numHosts}


    def sensor(self, sensor_id):
        sensor = self._get_redis("sensor-%d" % (sensor_id))
        if sensor:
            return sensor_id

        sensor = self._cb().sensor(sensor_id)

        self._set_redis("sensor-%d" % (sensor_id), sensor)
        return sensor

    def process_events(self, id, segment):
        proc_events = self._get_redis("proc-events-%s-%d" % (id, segment))
        if proc_events:
            return proc_events
        try:
            proc_events = self._cb().process_events(id, segment)
            self._set_redis("proc-events-%s-%d" % (id, segment), proc_events)
        except:
            return {}
        return proc_events


    def process_search(self, query_string, start=0, rows=10, sort="last_update desc", facet_enable=True):
        proc_search = self._get_redis("proc-search-%s" % query_string)
        if proc_search:
            return proc_search

        proc_search = self._cb().process_search(query_string, start, rows, sort, facet_enable)

        self._set_redis("proc-search-%s" % query_string, proc_search)
        return proc_search

    def binary_summary(self, md5):
        bin_summary = self._get_redis("bin-summary-%s" % md5)
        if bin_summary:
            return bin_summary

        try:
            bin_summary = self._cb().binary_summary(md5)
        except:
            return None

        self._set_redis("bin-summary-%s" % md5, bin_summary)
        return bin_summary


    def process_summary(self, guid, segment, children_count=15):
        proc = self._get_redis("proc-summary-%s-%d" % (guid, segment))
        if proc:
            return proc

        process_summary = self._cb().process_summary(guid, segment, children_count)

        self._set_redis("proc-summary-%s-%d" %(guid, segment), process_summary)
        return process_summary

    def process(self, process_id):
        """
        Get more data about the process
        """
        proc = self._get_redis("proc-%s" % process_id)
        if proc:
            return proc
        try:
            response = self._cb().process(process_id, 1)
        except:
            response = self._cb().process(process_id, 0)

        proc = response.get('process', {})
        self._set_redis("proc-%s" % process_id, proc)
        return proc

    def processes(self, query, start=0, rows=10, force_remote=False):
        key = "proc-%s-%d-%d" % (query, start, rows)
        proc = self._get_redis(key)
        if proc and not force_remote:
            return proc
        try:
            response, headers = self._cb().processes_with_headers(query, start=start, rows=rows)
        except:
            traceback.print_exc()
            return {}

        proc = response.get('results', [])
        self._set_redis(key, proc)
        return proc, headers

    def all_processes(self, query, force_remote=False):
        """
        This will loop until you get all the processes that hit your query.  It's usually faster to make multiple
        queries with 100 or 1000 rows than to try to get everything in one shot.
        """
        procs = []
        start = 0
        rows_per_request = 1000
        while True:
            cur = self.processes(query, start=start, rows=rows_per_request, force_remote=force_remote)
            procs += cur
            if len(cur) < rows_per_request:
                break
            start += rows_per_request
        return procs

    def binary(self, md5):
        if not md5:
            return {}

        md5 = md5.lower()
        binary = self._get_redis('bin-%s' % md5)
        if binary:
            return binary

        try:
            binary = self._cb().binary(md5)
        except:
            binary = {}

        self._set_redis('bin-%s' % md5, binary)
        return binary


