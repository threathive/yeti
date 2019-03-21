from __future__ import unicode_literals
import time

import logging

from flask_classy import route
from bson.json_util import loads
from flask import request, abort
from core.web.helpers import get_object_or_404
from core.web.api.crud import CrudSearchApi, CrudApi
from core import database, observables, entities, indicators
from core.web.api.api import render
from core.helpers import iterify
from core.investigation import Investigation
from core.web.helpers import requires_permissions


class LinkSearch(CrudSearchApi):
    objectmanager = database.Link


class Link(CrudApi):
    objectmanager = database.Link

    @requires_permissions('write')
    def delete(self, id):
        """Deletes the corresponding entry from the database

        :query ObjectID id: Element ID
        :>json string deleted: The deleted element's ObjectID
        """
        obj = self.objectmanager.objects.get(id=id)
        for i, inv in enumerate(Investigation.objects(links__id=id)):
            inv.modify({
                "links__id": id
            },
                       set__links__S__id="local-{}-{}".format(time.time(), i))
        obj.delete()
        return render({"deleted": id})

    @route("/multidelete", methods=['POST'])
    @requires_permissions('write')
    def multidelete(self):
        data = loads(request.data)
        ids = iterify(data['ids'])
        for i, inv in enumerate(Investigation.objects(links__id__in=ids)):
            inv.modify({
                "links__id": id
            },
                       set__links__S__id="local-{}-{}".format(time.time(), i))
        self.objectmanager.objects(id__in=ids).delete()
        return render({"deleted": ids})

    @route("/multiupdate", methods=['POST'])
    @requires_permissions('write')
    def multiupdate(self):
        data = loads(request.data)
        ids = data['ids']
        new_description = data['new']['description']
        updated = []
        for link in self.objectmanager.objects(id__in=ids):
            # link.select_related() #does not work
            # must call src and dst to dereference dbrefs and not raise an exception
            link.src
            link.dst
            link.description = new_description
            link.save()
            updated.append(link.id)

        return render({"updated": updated})

    @route("/", methods=['POST'])
    @requires_permissions('write')
    def new(self):
        """Create a new link

        Create a new link from the JSON object passed in the ``POST`` data.

        :<json object params: JSON object containing object ids to link
        """

        type_map = {
            'observable': observables.Observable,
            'entity': entities.Entity,
            'indicator': indicators.Indicator
        }

        mandatory_params = ['type_src', 'type_dst', 'link_src', 'link_dst']
        params = request.json

        if not all(key in params for key in mandatory_params):
            abort(400)

        type_src = params['type_src']
        type_dst = params['type_dst']
        src_object_class = type_map.get(type_src)
        dst_object_class = type_map.get(type_dst)

        if not src_object_class or not dst_object_class:
            abort(404)

        src = get_object_or_404(src_object_class, id=params["link_src"])
        dst = get_object_or_404(dst_object_class, id=params["link_dst"])
        try:
            if params.get("first_seen") and params.get("last_seen"):
                link = src.link_to(dst,
                                   params.get("description"),
                                   params.get("source"),
                                   params["first_seen"],
                                   params["last_seen"])
            else:
                link = src.active_link_to(dst,
                                          params.get("description"),
                                          params.get("source"))
        except Exception as e:
            logging.error(e)
            abort(400)

        return render({"link": link})
