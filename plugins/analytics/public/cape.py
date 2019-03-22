from __future__ import unicode_literals

import json
import logging
import requests
from core.analytics import OneShotAnalytics
from core.config.config import yeti_config
from core.observables import Hash, Text

class CapeApi(object):
    """
        Base class for querying the public Cape API.
    """

    @staticmethod
    def fetch(observable):
        """
        :param observable: The extended observable class
        :return: cape json response or None if error
        """

        hashes = {
            32: "md5",
            40: "sha1",
            64: "sha256",
        }

        try:
            response = None
            if isinstance(observable, Hash):
                hash_type = hashes.get( len(observable.value) )
                if hash_type:
                    response = requests.get( 
                        'https://cape.contextis.com/api/tasks/search/%s/%s/' % (hash_type, observable.value),
                        proxies=yeti_config.proxy
                    )
                else:
                    return None

                if response.ok:
                    return response.json()

            else:
                return None

        except Exception as e:
            logging.error('Exception while getting ip report {}'.format(e.message))
            return None

class CapeQuery(OneShotAnalytics, CapeApi):
    default_values = {
        'name': 'Cape',
        'group': 'Public Sandbox Data',
        'description': 'Lookup update reports related to a hash of interest.',
    }

    ACTS_ON = ['Hash']

    @staticmethod
    def analyze(observable, results):
        links = set()
        json_result = CapeApi.fetch(observable)
        json_string = json.dumps(
            json_result, sort_keys=True, indent=4, separators=(',', ': '))

        results.update(raw=json_string)

        result = dict([('raw', json_string), ('source', 'cape')])

        if json_result and json_result.get("error"):
            result['id'] = None
            result['url'] = None
            observable.add_context(result)
            return

        elif not json_result:
            result['id'] = None
            result['url'] = None
            observable.add_context(result)
            return

        elif isinstance(observable, Hash):
            _data = json_result.get("data", [])
            result['analysis'] = []
            for r in _data:
                if r.get("id"):
                    report = {
                        "url" : "https://cape.contextis.com/analysis/%s/" % str(r.get("id"))
                    }

                    sandbox_url = Text.get_or_create( 
                        value = "https://cape.contextis.com/analysis/%s/" % str(r.get("id") ))

                    links.update(
                        observable.active_link_to(sandbox_url, "analysis_link", 'cape_sandbox_run')
                    )

                    for k,v in r.items():
                        report[k] = v

                    result['analysis'].append(report)

            observable.add_context(result)
            return list(links)
