#########################################################################
#
# Copyright (C) 2020 OSGeo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#########################################################################
from drf_spectacular.utils import extend_schema

from dynamic_rest.viewsets import DynamicModelViewSet
from dynamic_rest.filters import DynamicFilterBackend, DynamicSortingFilter

from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.exceptions import AuthenticationFailed, NotFound

from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework.response import Response

from geonode.base.api.filters import DynamicSearchFilter, ExtentFilter
from geonode.base.api.permissions import IsOwnerOrReadOnly
from geonode.base.api.pagination import GeoNodeApiPagination
from geonode.layers.models import Dataset
from geonode.maps.api.serializers import SimpleMapLayerSerializer, SimpleMapSerializer
from geonode.layers.api.exceptions import LayerReplaceException
from geonode.layers.views import dataset_replace
from .serializers import DatasetSerializer, DatasetListSerializer
from .permissions import DatasetPermissionsFilter

import logging

logger = logging.getLogger(__name__)


class DatasetViewSet(DynamicModelViewSet):
    """
    API endpoint that allows layers to be viewed or edited.
    """
    authentication_classes = [SessionAuthentication, BasicAuthentication, OAuth2Authentication]
    permission_classes = [IsAuthenticatedOrReadOnly, IsOwnerOrReadOnly]
    filter_backends = [
        DynamicFilterBackend, DynamicSortingFilter, DynamicSearchFilter,
        ExtentFilter, DatasetPermissionsFilter
    ]
    queryset = Dataset.objects.all().order_by('-last_updated')
    serializer_class = DatasetSerializer
    pagination_class = GeoNodeApiPagination

    def get_serializer_class(self):
        if self.action == 'list':
            return DatasetListSerializer
        return DatasetSerializer

    @extend_schema(
        methods=["get"],
        responses={200: SimpleMapLayerSerializer(many=True)},
        description="API endpoint allowing to retrieve the MapLayers list.",
    )
    @action(detail=True, methods=["get"])
    def maplayers(self, request, pk=None):
        dataset = self.get_object()
        resources = dataset.maplayers
        return Response(SimpleMapLayerSerializer(many=True).to_representation(resources))

    @extend_schema(
        methods=["get"],
        responses={200: SimpleMapSerializer(many=True)},
        description="API endpoint allowing to retrieve maps using the dataset.",
    )
    @action(detail=True, methods=["get"])
    def maps(self, request, pk=None):
        dataset = self.get_object()
        resources = dataset.maps
        return Response(SimpleMapSerializer(many=True).to_representation(resources))

    @extend_schema(
        methods=["post"],
        responses={200},
        description="API endpoint allowing to replace a dataset."
    )
    @action(
        detail=False,
        url_path="(?P<dataset_id>\d+)/replace",  # noqa
        url_name="replace-dataset",
        methods=["post"]
    )
    def replace(self, request, dataset_id=None):
        user = request.user
        if not user or not user.is_authenticated:
            raise AuthenticationFailed

        if not self.queryset.filter(id=dataset_id).exists():
            raise NotFound(detail=f"Layer with ID {dataset_id} is not available")

        alternate = self.queryset.get(id=dataset_id).alternate

        response = dataset_replace(request=request, layername=alternate)

        if response.status_code != 200:
            raise LayerReplaceException(detail=response.content)

        return response
