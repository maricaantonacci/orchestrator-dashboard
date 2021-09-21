# Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2019-2020
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from flask import Blueprint, render_template, flash, request
from app.providers import sla
from app import app
from app.lib import auth, settings
import requests


providers_bp = Blueprint('providers_bp', __name__, template_folder='templates', static_folder='static')


@providers_bp.route('/slas')
@auth.authorized_with_valid_token
def getslas():
    slas = {}

    try:
        access_token = app.get_auth_blueprint().session.token['access_token']
        app.logger.debug("SLAM_URL: {}".format(settings.orchestratorConf['slam_url']))
        slas = sla.get_slas(access_token, settings.orchestratorConf['slam_url'], settings.orchestratorConf['cmdb_url'])
        app.logger.debug("SLAs: {}".format(slas))

    except Exception as e:
        flash("Error retrieving SLAs list: \n" + str(e), 'warning')

    return render_template('sla.html', slas=slas)


@providers_bp.route('/get_monitoring_info')
@auth.authorized_with_valid_token
def get_monitoring_info():
    provider = request.args.get('provider', None)
    serviceid = request.args.get('service_id', None)
    # servicetype = request.args.get('service_type',None)

    access_token = app.get_auth_blueprint().session.token['access_token']

    headers = {'Authorization': 'bearer %s' % access_token}
    url = settings.orchestratorConf[
              'monitoring_url'] + "/monitoring/adapters/zabbix/zones/indigo/types/infrastructure/groups/" + \
          provider + "/hosts/" + serviceid
    response = requests.get(url, headers=headers)

    monitoring_data = {}

    if response.ok:
        try:
            monitoring_data = response.json()['result']['groups'][0]['paasMachines'][0]['services'][0]['paasMetrics']
        except Exception as e:
            app.logger.debug("Error getting monitoring data")

    return render_template('monitoring_metrics.html', monitoring_data=monitoring_data)
