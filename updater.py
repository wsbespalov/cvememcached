import re
import string
import bson
import json
import time
import urllib
import urllib.request as req
import zipfile
from io import BytesIO
import gzip
import bz2
import sys
import json
import ast
import telnetlib
import cpe as cpe_module
from dateutil.parser import parse as parse_datetime
from datetime import datetime
from functools import  lru_cache

from pymemcache.client import base as memcached_base

SETTINGS = {
    "memcached": {
        "host": "localhost",
        "port": 11211,
        "key_prefix": "index::",
        "separator": "::",
        "drop_cache_before": True,
    },
    "sources": {
        "cve_modified": "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz",
        "cve_recent": "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz",
        "cve_base": "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-",
        "cve_base_postfix": ".json.gz",
        "cpe22": "https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml.zip",
        "cpe23": "https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip",
        "cwe": "http://cwe.mitre.org/data/xml/cwec_v2.8.xml.zip",
        "capec": "http://capec.mitre.org/data/xml/capec_v2.6.xml",
        "ms": "http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx",
        "d2sec": "http://www.d2sec.com/exploits/elliot.xml",
        "npm": "https://api.nodesecurity.io/advisories",
    },
    "start_year": 2011,
}

def progressbar(it, prefix="Processing ", size=50):
    count = len(it)

    def _show(_i):
        if count != 0 and sys.stdout.isatty():
            x = int(size * _i / count)
            sys.stdout.write("%s[%s%s] %i/%i\r" % (prefix, "#" * x, " " * (size - x), _i, count))
            sys.stdout.flush()

    _show(0)
    for i, item in enumerate(it):
        yield item
        _show(i + 1)
    sys.stdout.write("\n")
    sys.stdout.flush()


class CVEItem(object):
    def __init__(self, data):
        cve = data.get("cve", {})
        # Get Data Type -> str
        self.data_type = cve.get("data_type", None)
        # Get Data Format -> str
        self.data_format = cve.get("data_format", None)
        # Get Data Version -> str
        self.data_version = cve.get("data_version", None)  # Data version like 4.0
        # Get CVE ID like CVE-2002-2446 -> str
        CVE_data_meta = cve.get("CVE_data_meta", {})
        self.cve_id = CVE_data_meta.get("ID", None)
        # GET CWEs -> JSON with list -> {"data": cwe}
        cwe = []
        problemtype = cve.get("problemtype", {})
        problemtype_data = problemtype.get("problemtype_data", [])
        for pd in problemtype_data:
            description = pd.get("description", [])
            for d in description:
                value = d.get("value", None)
                if value is not None:
                    cwe.append(value)
        self.cwe = {"data": cwe}
        # GET RREFERENCES -> JSON with list -> {"data": references}
        references = []
        ref = cve.get("references", {})
        reference_data = ref.get("reference_data", [])
        for rd in reference_data:
            url = rd.get("url", None)
            if url is not None:
                references.append(url)
        self.references = {"data": references}
        # GET DESCRIPTION -> str
        self.description = ""
        descr = cve.get("description", {})
        description_data = descr.get("description_data", [])
        for dd in description_data:
            value = dd.get("value", "")
            self.description = self.description + value
        # GET cpe -> JSON with list -> {"data": cpe22}
        cpe22 = []
        conf = data.get("configurations", {})
        nodes = conf.get("nodes", [])
        for n in nodes:
            cpe = n.get("cpe", [])
            for c in cpe:
                c22 = c.get("cpe22Uri", None)
                cpe22.append(c22)
        self.vulnerable_configuration = {"data": cpe22}
        self.cpe = ""
        self.published = data.get("publishedDate", datetime.utcnow())
        self.modified = data.get("lastModifiedDate", datetime.utcnow())

        # access
        impact = data.get("impact", {})

        self.access = {}
        baseMetricV2 = impact.get("baseMetricV2", {})
        cvssV2 = baseMetricV2.get("cvssV2", {})
        self.access["vector"] = cvssV2.get("accessVector", "")
        self.access["complexity"] = cvssV2.get("accessComplexity", "")
        self.access["authentication"] = cvssV2.get("authentication", "")

        # impact
        self.impact = {}
        self.impact["confidentiality"] = cvssV2.get("confidentialityImpact", "")
        self.impact["integrity"] = cvssV2.get("integrityImpact", "")
        self.impact["availability"] = cvssV2.get("availabilityImpact", "")

        # vector_string
        self.vector_string = cvssV2.get("vectorString", "")

        # baseScore - cvss
        self.cvss = cvssV2.get("baseScore", "")

        # Additional fields
        self.component = ""
        self.version = ""

    def to_json(self):
        return json.dumps(self,
                          default=lambda o: o.__dict__,
                          sort_keys=True)


class InMemoryCache(object):

    cache = {}

    @property
    def size(self):
        return len(self.cache)

    def __contains__(self, key):
        return key in self.cache

    @lru_cache(maxsize=None, typed=False)
    def get(self, key):
        if self.__contains__(key):
            return self.cache[key]
        else:
            return None

    @lru_cache(maxsize=None, typed=False)
    def set(self, key, data):
        self.cache[key] = data

    def create_key__str(self, component: str, version: str) -> str:
        return "".join([
            SETTINGS["memcached"]["key_prefix"],
            component,
            SETTINGS["memcached"]["separator"],
            version
        ])

    def serialize_bson__bytes(self, data: dict) -> bytes:
        try:
            return bson.dumps(data)
        except Exception as ex:
            pass
        pass

    def deserialize_bson__dict(self, data: bytes) -> dict:
        try:
            return bson.loads(data)
        except Exception as ex:
            pass
        pass

    def append_data_to_key(self, key: str, data_to_append: dict) -> int:
        data_from_cache = self.get_deserialized_data_from_key(key)
        data_list = data_from_cache.get("data", [])
        data_list.append(data_to_append)
        data_for_cache = dict(data=[])
        data_for_cache["data"] = data_list
        self.set_serialized_data_to_key(key, data_for_cache)
        return len(data_list)

    def get_deserialized_data_from_key(self, key: str) -> dict:
        try:
            data = self.cache.get(key)
            if data is None:
                return dict(data=[])
            return self.deserialize_bson__dict(data)
        except Exception as ex:
            return dict(data=[])
        pass

    def set_serialized_data_to_key(self, key: str, data_to_cache: dict):
        data_to_set = self.serialize_bson__bytes(data_to_cache)
        try:
            self.cache.set(key, data_to_set)
        except Exception as ex:
            pass
        pass

class MCache(object):
    def __init__(self):
        self._host = SETTINGS["memcached"]["host"]
        self._port = SETTINGS["memcached"]["port"]
        self._cache_client = memcached_base.Client(
            (self._host, self._port)
        )
        if SETTINGS["memcached"]["drop_cache_before"]:
            self._cache_client.flush_all()
        self._key_regex = re.compile(u'ITEM (.*) \[(.*); (.*)\]')
        self._slab_regex = re.compile(u'STAT items:(.*):number')
        self._stat_regex = re.compile(u"STAT (.*) (.*)\r")
        self._client = None

    @property
    def client(self):
        if self._client is None:
            self._client = telnetlib.Telnet(self._host, self._port)
        return self._client

    def command(self, cmd):
        self.client.write(("%s\n" % cmd).encode("ascii"))
        return self.client.read_all()

    def key_details(self, sort=True, limit=100):
        cmd = 'stats cachedump %s %s'
        keys = [key for id in self.slab_ids()
                for key in self._key_regex.findall(self.command(cmd % (id, limit)))]
        if sort:
            return sorted(keys)
        else:
            return keys

    def keys(self, sort=True, limit=100):
        return [key[0] for key in self.key_details(sort=sort, limit=limit)]

    def slab_ids(self):
        return self._slab_regex.findall(self.command('stats items'))

    def stats(self):
        return dict(self._stat_regex.findall(self.command('stats')))

    def serialize_bson__bytes(self, data: dict) -> bytes:
        try:
            return bson.dumps(data)
        except Exception as ex:
            pass
        pass

    def deserialize_bson__dict(self, data: bytes) -> dict:
        try:
            return bson.loads(data)
        except Exception as ex:
            pass
        pass

    def delete_key(self, key: str):
        try:
            return self._cache_client.delete(key=key)
        except Exception as ex:
            pass
        pass

    def create_key__str(self, component: str, version: str) -> str:
        return "".join([
            SETTINGS["memcached"]["key_prefix"],
            component,
            SETTINGS["memcached"]["separator"],
            version
        ])

    def append_data_to_key(self, key: str, data_to_append: dict) -> int:
        data_from_cache = self.get_deserialized_data_from_key(key)
        data_list = data_from_cache.get("data", [])
        data_list.append(data_to_append)
        data_for_cache = dict(data=[])
        data_for_cache["data"] = data_list
        self.set_serialized_data_to_key(key, data_for_cache)
        return len(data_list)

    def get_deserialized_data_from_key(self, key: str) -> dict:
        try:
            data = self._cache_client.get(key)
            if data is None:
                return dict(data=[])
            return self.deserialize_bson__dict(data)
        except Exception as ex:
            return dict(data=[])
        pass

    def set_serialized_data_to_key(self, key: str, data_to_cache: dict):
        data_to_set = self.serialize_bson__bytes(data_to_cache)
        try:
            self._cache_client.set(key, data_to_set)
        except Exception as ex:
            pass
        pass


class Utils(object):
    def unify_time(self, dt):
        if isinstance(dt, str):
            if 'Z' in dt:
                dt = dt.replace('Z', '')
            return parse_datetime(dt)
        if isinstance(dt, datetime):
            return parse_datetime(str(dt))
    def get_file(self, getfile, unpack=True, raw=False, HTTP_PROXY=None):
        try:
            if HTTP_PROXY:
                proxy = req.ProxyHandler({'http': HTTP_PROXY, 'https': HTTP_PROXY})
                auth = req.HTTPBasicAuthHandler()
                opener = req.build_opener(proxy, auth, req.HTTPHandler)
                req.install_opener(opener)
            data = response = req.urlopen(getfile)
            if raw:
                return data
            if unpack:
                if 'gzip' in response.info().get('Content-Type'):
                    buf = BytesIO(response.read())
                    data = gzip.GzipFile(fileobj=buf)
                elif 'bzip2' in response.info().get('Content-Type'):
                    data = BytesIO(bz2.decompress(response.read()))
                elif 'zip' in response.info().get('Content-Type'):
                    fzip = zipfile.ZipFile(BytesIO(response.read()), 'r')
                    length_of_namelist = len(fzip.namelist())
                    if length_of_namelist > 0:
                        data = BytesIO(fzip.read(fzip.namelist()[0]))
            return data, response
        except Exception as ex:
            return None, str(ex)
    def download_cve_file(self, source):
        file_stream, response_info = self.get_file(source)
        try:
            result = json.load(file_stream)
            if "CVE_Items" in result:
                CVE_data_timestamp = result.get("CVE_data_timestamp", self.unify_time(dt=datetime.utcnow()))
                return result["CVE_Items"], CVE_data_timestamp, response_info
            return None
        except json.JSONDecodeError as json_error:
            print('Get an JSON decode error: {}'.format(json_error))
            return None
    def parse_cve_file(self, items=None, CVE_data_timestamp=None):
        if CVE_data_timestamp is None:
            CVE_data_timestamp = self.unify_time(dt=datetime.utcnow())
        if items is None:
            items = []
        parsed_items = []
        for item in items:
            element = json.loads(CVEItem(item).to_json())
            element["cvss_time"] = CVE_data_timestamp
            parsed_items.append(element)
        return parsed_items


class VUpdater(object):

    def __init__(self):
        # self.cache = MCache()
        self.cache = InMemoryCache()
        self.utils = Utils()

    def filter_cpe_string__json(self, element):
        result = {"component": None, "version": None}
        try:
            c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_2_2)
        except ValueError as value_error:
            try:
                c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_2_3)
            except ValueError as another_value_error:
                try:
                    c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_UNDEFINED)
                except NotImplementedError as not_implemented_error:
                    c22 = None
        c22_product = c22.get_product() if c22 is not None else []
        c22_version = c22.get_version() if c22 is not None else []
        result["component"] = c22_product[0] if isinstance(c22_product, list) and len(c22_product) > 0 else None
        result["version"] = c22_version[0] if isinstance(c22_version, list) and len(c22_version) > 0 else None
        return result

    def filter_items_to_update(self, items_fo_filter, unquote=True, only_digits_and_dot_in_version=True):
        filtered_items = []
        # for item in items_fo_filter:
        for item in progressbar(items_fo_filter, prefix='Filtering  '):
            # For every item in downloaded update
            # Get cpe strings
            list_of_cpe_strings_field = item.get("vulnerable_configuration", {})
            list_of_cpe_strings = list_of_cpe_strings_field.get("data", [])
            # If list not empty
            if len(list_of_cpe_strings) > 0:
                # For every cpe string
                for one_cpe_string in list_of_cpe_strings:
                    # Get one string and check it
                    filtered_cpe_string = self.filter_cpe_string__json(one_cpe_string)
                    version = filtered_cpe_string.get("version", "")
                    component = filtered_cpe_string.get("component", "")
                    if version is not None and not str(version).__eq__(""):
                        if component is not None and not str(component).__eq__(""):
                            # Copy item into filtered items
                            new_item = {}
                            new_item = item.copy()
                            new_item["component"] = filtered_cpe_string["component"]
                            new_item["version"] = filtered_cpe_string["version"]
                            if unquote:
                                try:
                                    new_item["version"] = urllib.parse.unquote(new_item["version"])
                                except:
                                    pass
                            if only_digits_and_dot_in_version:
                                allow = string.digits + '.' + '(' + ')'
                                new_item["version"] = re.sub('[^%s]' % allow, '', new_item["version"])
                            new_item["vulnerable_configuration"] = {"data": list_of_cpe_strings}
                            new_item["cpe"] = one_cpe_string
                            filtered_items.append(new_item)
                            del new_item
        return filtered_items

    def update_vulnerabilities_table__counts(self, items_to_update):
        start_time = time.time()
        count_of_new_records = 0
        count_of_updated_records = 0

        for one_item in progressbar(items_to_update):
            # create key
            key = self.cache.create_key__str(component=one_item["component"], version=one_item["version"])
            # check in already in
            data__dict = self.cache.get_deserialized_data_from_key(key=key)
            data_list = data__dict.get("data", [])
            not_found = True
            for data in data_list:
                if data["component"] == one_item["component"] and \
                    data["version"] == one_item["version"] and \
                    self.utils.unify_time(data["published"]) == self.utils.unify_time(one_item["published"]) and \
                        self.utils.unify_time(data["modified"]) == self.utils.unify_time(one_item["modified"]):
                    not_found = False
                    break
                else:
                    pass
            # append key
            if not_found:
                # so, was found
                self.cache.append_data_to_key(key=key, data_to_append=one_item)
            pass

        return count_of_new_records, count_of_updated_records, time.time() - start_time

    def populate(self):
        start_time = time.time()
        start_year = SETTINGS.get("start_year", 2012)
        current_year = datetime.now().year
        count_of_parsed_cve_items = 0
        count_of_populated_items = 0
        for year in range(start_year, current_year + 1):
            print("Populate CVE-{}".format(year))
            source = SETTINGS["sources"]["cve_base"] + str(year) + SETTINGS["sources"]["cve_base_postfix"]
            cve_item, CVE_data_timestamp, response = self.utils.download_cve_file(source)
            parsed_cve_items = self.utils.parse_cve_file(cve_item, CVE_data_timestamp)
            items_to_populate = self.filter_items_to_update(parsed_cve_items)
            self.update_vulnerabilities_table__counts(items_to_populate)
            count_of_parsed_cve_items += len(parsed_cve_items)
            count_of_populated_items += len(items_to_populate)
        return count_of_parsed_cve_items, count_of_populated_items, time.time() - start_time

def test():
    u = VUpdater()
    count_of_parsed_cve_items, count_of_populated_items, time_delta = u.populate()
    print("Complete populate {} from {} elements in {} sec.".format(
        count_of_parsed_cve_items,
        count_of_populated_items,
        time_delta
    ))

test()
