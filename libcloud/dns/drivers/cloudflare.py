# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__all__ = [
    'CloudFlareDNSDriver'
]

from libcloud.utils.py3 import httplib

try:
    import simplejson as json
except:
    import json

import datetime

from libcloud.common.base import JsonResponse, ConnectionUserAndKey
from libcloud.common.types import InvalidCredsError, LibcloudError
from libcloud.common.types import MalformedResponseError, LazyList
from libcloud.dns.base import DNSDriver, Zone, Record
from libcloud.dns.types import Provider, RecordType
from libcloud.dns.types import ZoneDoesNotExistError, ZoneAlreadyExistsError
from libcloud.dns.types import RecordDoesNotExistError
from libcloud.dns.types import RecordAlreadyExistsError

API_HOST = 'cloudflare.com'
API_ACTION = '/api_json.html'

class CloudFlareDNSError(LibcloudError):
    def __init__(self, code, err_code, err_msg):
        self.code = code
        self.err_code = err_code
        self.err_msg = err_msg
    
    def __str__(self):
        return 'Error: %s\n%s' % (self.err_code, self.err_msg)
    
    def __repr__(self):
        return ('<CloudFlareError response code=%s error code=%s>' % 
                                 (self.code, self.err_code))
    

class CloudFlareDNSResponse(JsonResponse):
    def success(self):
        body = json.loads(self.body)
        if body['result'] == 'success':
            return self.status == httplib.OK
    
    def parse_error(self):
        status = int(self.status)
        
        if status == 401:
            if not self.body:
                raise InvalidCredsError(str(self.status) + ': ' + self.error)
            else:
                raise InvalidCredsError(self.body)
        elif status != 503:
            try:
                body = json.loads(self.body)
            except:
                raise MalformedResponseError('Failed to parse Json',
                                             body=self.body)
            
            raise CloudFlareDNSError(code=status,
                                     err_code=body['err_code'],
                                     err_msg=body['msg'])
        
        return self.body
    

class CloudFlareDNSConnection(ConnectionUserAndKey):
    host = API_HOST
    secure = True
    responseCls = CloudFlareDNSResponse
    
    def request(self, action, params=None, data='', headers=None,
                method='POST'):
        if not headers:
            headers = {'Content-Type': 'application/json; charset=UTF-8'}
        if not params:
            params = {}
        
        params['u'] = self.user_id
        params['tkn'] = self.key
        return super(CloudFlareDNSConnection, self).request(action=action,
                                                            params=params,
                                                            data=data,
                                                            method=method,
                                                            headers=headers)
    


class CloudFlareDNSDriver(DNSDriver):
    type = Provider.CLOUDFLARE
    name = 'CloudFlare DNS'
    connectionCls = CloudFlareDNSConnection

    RECORD_TYPE_MAP = {
        RecordType.A: 'A',
        RecordType.CNAME: 'CNAME',
    }
    
    def current_stats(self, zone_id, interval=20):
        params = {'a': 'stats',
                  'z': zone_id,
                  'interval': interval}
        response = self.connection.request(action=API_ACTION, params=params)
        stats = json.loads(response.body)['response']['result']
        return stats
    
    def set_security_level(self, zone_id, level):
        sec_lvls = ['high','med','low','eoff']
        if level not in sec_lvls:
            raise CloudFlareDNSError(code=httplib.BAD_REQUEST,
                    err_code='E_INVLDINPUT',
                    err_msg='Level must be in ' + sec_lvls)
        params = {'a': 'sec_lvl',
                  'z': zone_id,
                  'v': level}
        response = self.connection.request(action=API_ACTION, params=params)
        return response.status == httplib.OK
    
    def set_cache_level(self, zone_id, level):
        cache_lvls = ['agg','basic']
        if level not in cache_lvls:
            raise CloudFlareDNSError(code=httplib.BAD_REQUEST,
                    err_code='E_INVLDINPUT',
                    err_msg='Level must be in ' + cache_lvls)
        params = {'a': 'cache_lvl',
                  'z': zone_id,
                  'v': level}
        response = self.connection.request(action=API_ACTION, params=params)
        return response.status == httplib.OK
    
    def set_development_mode(self, zone_id, mode):
        if type(mode) != bool:
            raise CloudFlareDNSError(code=httplib.BAD_REQUEST,
                    err_code='E_INVLDINPUT',
                    err_msg='Mode must be boolean')
        params = {'a': 'devmode',
                  'z': zone_id,
                  'v': int(mode)}
        response = self.connection.request(action=API_ACTION, params=params)
        assert response.status == httplib.OK
        expires_on = json.loads(response.body)['response']['expires_on']
        return datetime.datetime.fromtimestamp(expires_on).ctime()
    
    def purge_cache(self, zone_id):
        params = {'a': 'fpurge_ts',
                  'z': zone_id,
                  'v': 1}
        response = self.connection.request(action=API_ACTION, params=params)
        fpurge_ts = json.loads(response.body)['response']['fpurge_ts']
        return datetime.datetime.fromtimestamp(fpurge_ts).ctime()
    
    def purge_preloader_cache(self, zone_id):
        params = {'a': 'pre_purge',
                  'zone_name': zone_id}
        response = self.connection.request(action='/ajax/external-event.html',
                                            params=params)
        return response.status == httplib.OK
    
    def zone_check(self, zones):
        params = {'a': 'zone_check',
                  'zones': zones}
        response = self.connection.request(action=API_ACTION, params=params)
        zones = json.loads(response.body)['response']['zones']
        return zones
    
    def zone_ips(self, zone_id, hours=24, **kwargs):
        params = {'a': 'zone_ips',
                  'zid': zone_id}
        
        if 'hours' in kwargs.keys():
            params['hours'] = kwargs['hours']
        if 'class' in kwargs.keys():
            params['class'] = kwargs['class']
        if 'geo' in kwargs.keys():
            params['geo'] = kwargs['geo']
        
        response = self.connection.request(action=API_ACTION, params=params)
        ips = json.loads(response.body)['response']['ips']
        return ips
    
    def zone_grab(self, zone_id):
        params = {'a': 'zone_grab',
                  'z': zone_id}
        response = self.connection.request(action=API_ACTION, params=params)
        assert response.status == httplib.OK
        set = json.loads(response.body)['response']['set']
        return set
    
    def report_spam(self, spam_array):
        params = {'evnt_t': 'CF_USER_SPAM',
                  'evnt_v': spam_array}
        response = self.connection.request(action='/ajax/external-event.html',
                                            params=params)
        return response.status == httplib.OK
    
    def whitelist_ip(self, ip):
        params = {'a': 'wl',
                  'key': ip}
        response = self.connection.request(action=API_ACTION, params=params)
        return response.status == httplib.OK
    
    def blacklist_ip(self, ip):
        params = {'a': 'ban',
                  'key': ip}
        response = self.connection.request(action=API_ACTION, params=params)
        return response.status == httplib.OK
    
    def create_record(self, name, zone, type, data, extra=None):
        params = {'a': 'rec_set',
                  'name': name,
                  'zone': zone,
                  'type': type,
                  'content': data,
                  'service_mode': int(extra)}
        response = self.connection.request(action=API_ACTION, params=params)
        assert response.status == httplib.OK
        record = Record(id=id, name=name, type=type, data=data, extra=extra,
                        zone=zone, driver=self)
        return record

    def delete_record(self, zone_id, record):
        params = {'a': 'rec_del',
                  'zone': zone_id,
                  'name': record}
        response = self.connection.request(action=API_ACTION, params=params)
        return response.status == httplib.OK
    
    def update_record(self, record, name=None, type=None, data, extra=None):
        params = {'a': 'DIUP',
                  'hosts': record,
                  'ip': data}
        response = self.connection.request(action=API_ACTION, params=params)
        return response.status == httplib.OK
    
    def ip_check(self, ip):
        params = {'a': 'ip_lkup',
                  'ip': ip}
        response = self.connection.request(action=API_ACTION, params=params)
        assert response.status == httplib.OK
        ip = json.loads(response.body)['response']
        return ip
    
    def toggle_ipv6(self, zone_id, mode):
        if type(mode) != bool:
            raise CloudFlareDNSError(code=httplib.BAD_REQUEST,
                    err_code='E_INVLDINPUT',
                    err_msg='Mode must be boolean')
        params = {'a': 'ipv46',
                  'z': zone_id,
                  'v': int(mode)}
        response = self.connection.request(action=API_ACTION, params=params)
        return response.status == httplib.OK
    
if __name__ == "__main__":
    import doctest
    doctest.testmod()
