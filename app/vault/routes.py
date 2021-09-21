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

from flask import Blueprint, render_template, flash, request, redirect, url_for, session, json
from app import app, vaultservice
from app.lib import auth, sshkey as sshkeyhelpers, settings, dbhelpers
from app.providers import sla
from app.models.Deployment import Deployment
from app.models.User import User


vault_bp = Blueprint('vault_bp', __name__, template_folder='templates', static_folder='static')

iam_base_url = settings.iamUrl
iam_client_id = settings.iamClientID
iam_client_secret = settings.iamClientSecret

issuer = settings.iamUrl
if not issuer.endswith('/'):
    issuer += '/'

@vault_bp.route('/read_secret/<depid>')
@auth.authorized_with_valid_token
def read_secret(depid=None):

    vault_bound_audience = app.config.get('VAULT_BOUND_AUDIENCE')
    vault_mountpoint_kv1 = app.config.get('VAULT_MOUNTPOINT_KV1')
    vault_mountpoint_kv2 = app.config.get('VAULT_MOUNTPOINT_KV2')
    vault_role = app.config.get("VAULT_ROLE")
    vault_read_policy = app.config.get("READ_POLICY")
    vault_read_token_time_duration = app.config.get("READ_TOKEN_TIME_DURATION")
    vault_read_token_renewal_duration = app.config.get("READ_TOKEN_RENEWAL_TIME_DURATION")

    access_token = app.get_auth_blueprint().session.token['access_token']

    # retrieve deployment from DB
    dep = dbhelpers.get_deployment(depid)
    if dep is None:
        return redirect(url_for('home_bp.home'))
    else:

        jwt_token = auth.exchange_token_with_audience(iam_base_url,
                                                      iam_client_id,
                                                      iam_client_secret,
                                                      access_token,
                                                      vault_bound_audience)

        vault_client = vaultservice.connect(jwt_token, vault_role)

        read_token = vault_client.get_token(vault_read_policy,
                                            vault_read_token_time_duration,
                                            vault_read_token_renewal_duration)

        # retrieval of secret_path and secret_key from the db goes here
        secret_path = session['userid'] + "/" + dep.vault_secret_uuid
        user_key = dep.vault_secret_key

        response_output = vault_client.read_secret(read_token, secret_path, user_key)

        vault_client.revoke_token()

        return response_output


@vault_bp.route('/create_ssh_key/<subject>')
@auth.authorized_with_valid_token
def create_ssh_key(subject):
    access_token = app.get_auth_blueprint().session.token['access_token']
    privkey, pubkey = sshkeyhelpers.generate_ssh_key()
    privkey = privkey.decode("utf-8").replace("\n", "\\n")
    store_privkey(access_token, privkey)

    dbhelpers.update_user(subject, dict(sshkey=pubkey.decode("utf-8")))

    return redirect(url_for('vault_bp.ssh_keys'))


@vault_bp.route('/ssh_keys')
@auth.authorized_with_valid_token
def ssh_keys():
    sshkey = dbhelpers.get_ssh_pub_key(session['userid'])
    return render_template('ssh_keys.html', sshkey=sshkey)


def store_privkey(access_token, privkey_value):

    vault_bound_audience = app.config.get('VAULT_BOUND_AUDIENCE')
    vault_mountpoint_kv1 = app.config.get('VAULT_MOUNTPOINT_KV1')
    vault_mountpoint_kv2 = app.config.get('VAULT_MOUNTPOINT_KV2')
    vault_role = app.config.get("VAULT_ROLE")
    vault_write_policy = app.config.get("WRITE_POLICY")
    vault_write_token_time_duration = app.config.get("WRITE_TOKEN_TIME_DURATION")
    vault_write_token_renewal_time_duration = app.config.get("WRITE_TOKEN_RENEWAL_TIME_DURATION")

    jwt_token = auth.exchange_token_with_audience(iam_base_url,
                                                  iam_client_id, iam_client_secret, access_token, vault_bound_audience)

    vault_client = vaultservice.connect(jwt_token, vault_role)

    write_token = vault_client.get_token(vault_write_policy, vault_write_token_time_duration, vault_write_token_renewal_time_duration)
    
    secret_path = session['userid'] + '/ssh_private_key'
    privkey_key = 'ssh_private_key'

    response_output = vault_client.write_secret(write_token, secret_path, privkey_key, privkey_value)

    vault_client.revoke_token()

    return response_output


@vault_bp.route('/read_privkey/<subject>')
@auth.authorized_with_valid_token
def read_privkey(subject):

    vault_bound_audience = app.config.get('VAULT_BOUND_AUDIENCE')
    vault_mountpoint_kv1 = app.config.get('VAULT_MOUNTPOINT_KV1')
    vault_mountpoint_kv2 = app.config.get('VAULT_MOUNTPOINT_KV2')
    vault_role = app.config.get("VAULT_ROLE")
    vault_read_policy = app.config.get("READ_POLICY")
    vault_read_token_time_duration = app.config.get("READ_TOKEN_TIME_DURATION")
    vault_read_token_renewal_duration = app.config.get("READ_TOKEN_RENEWAL_TIME_DURATION")

    access_token = app.get_auth_blueprint().session.token['access_token']

    jwt_token = auth.exchange_token_with_audience(iam_base_url,
                                                  iam_client_id, iam_client_secret, access_token, vault_bound_audience)

    vault_client = vaultservice.connect(jwt_token, vault_role)

    read_token = vault_client.get_token(vault_read_policy, vault_read_token_time_duration,
                                 vault_read_token_renewal_duration)

    secret_path = session['userid'] + '/ssh_private_key'
    privkey_key = 'ssh_private_key'

    response_output = vault_client.read_secret(read_token, secret_path, privkey_key)

    vault_client.revoke_token()

    return response_output

@vault_bp.route('/delete_ssh_key/<subject>')
@auth.authorized_with_valid_token
def delete_ssh_key(subject):

    vault_bound_audience = app.config.get('VAULT_BOUND_AUDIENCE')
    vault_mountpoint_kv1 = app.config.get('VAULT_MOUNTPOINT_KV1')
    vault_mountpoint_kv2 = app.config.get('VAULT_MOUNTPOINT_KV2')
    vault_role = app.config.get("VAULT_ROLE")
    vault_delete_policy = app.config.get("DELETE_POLICY")
    vault_delete_token_time_duration = app.config.get("DELETE_TOKEN_TIME_DURATION")
    vault_delete_token_renewal_time_duration = app.config.get("DELETE_TOKEN_RENEWAL_TIME_DURATION")

    dbhelpers.delete_ssh_key(subject)

    access_token = app.get_auth_blueprint().session.token['access_token']
    privkey_key = session['userid'] + '/ssh_private_key'

    jwt_token = auth.exchange_token_with_audience(iam_base_url,
                                                  iam_client_id, iam_client_secret, access_token, vault_bound_audience)

    vault_client = vaultservice.connect(jwt_token, vault_role)

    delete_token = vault_client.get_token(vault_delete_policy, vault_delete_token_time_duration,
                                   vault_delete_token_renewal_time_duration)

    vault_client.delete_secret(delete_token, privkey_key)

    return redirect(url_for('vault_bp.ssh_keys'))


@vault_bp.route('/update_ssh_key/<subject>', methods=['POST'])
@auth.authorized_with_valid_token
def update_ssh_key(subject):

    sshkey = request.form['sshkey']
    if sshkey == "" or str(sshkeyhelpers.check_ssh_key(sshkey.encode())) != "0":
        flash("Invaild SSH public key. Please insert a correct one.", 'warning')
        return redirect(url_for('vault_bp.ssh_keys'))

    dbhelpers.update_user(subject, dict(sshkey=sshkey))

    return redirect(url_for('vault_bp.ssh_keys'))

@vault_bp.route('/manage_credentials')
@auth.authorized_with_valid_token
def manage_service_creds():
  slas={}

  try:
    access_token = app.get_auth_blueprint().session.token['access_token']
    slas = sla.get_slas(access_token, settings.orchestratorConf['slam_url'], settings.orchestratorConf['cmdb_url'])
    app.logger.debug("Service details: {}".format(slas))

  except Exception as e:
        flash("Error retrieving SLAs list: \n" + str(e), 'warning')

  return render_template('service_creds.html', slas=slas)


@vault_bp.route('/read_credentials')
@auth.authorized_with_valid_token
def read_service_creds():
    vault_bound_audience = app.config.get('VAULT_BOUND_AUDIENCE')
    vault_role = app.config.get("VAULT_ROLE")

    serviceid = request.args.get('service_id', None)
    servicetype = request.args.get('service_type', None)

    access_token = app.get_auth_blueprint().session.token['access_token']
    jwt_token = auth.exchange_token_with_audience(iam_base_url,
                                                  iam_client_id, iam_client_secret, access_token, vault_bound_audience)

    vault_client = vaultservice.connect(jwt_token, vault_role)
    path = "services_credential/" + serviceid
    secret = vault_client.read_service_creds(path)

    if secret:
        secret = secret.get('data')

    return render_template('modal_creds.html', mode="filled-form", service_creds=secret, service_type=servicetype)


@vault_bp.route('/write_credentials', methods=['GET', 'POST'])
@auth.authorized_with_valid_token
def write_service_creds():
    vault_bound_audience = app.config.get('VAULT_BOUND_AUDIENCE')
    vault_role = app.config.get("VAULT_ROLE")

    serviceid = request.args.get('service_id', "")
    servicetype = request.args.get('service_type', "")

    app.logger.debug("service_id={}".format(serviceid))

    if request.method == 'GET':
        return render_template('modal_creds.html', mode="empty-form", service_creds=None, service_type=servicetype,
                               service_id=serviceid)
    else:

        app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

        creds = request.form.to_dict()

        access_token = app.get_auth_blueprint().session.token['access_token']

        jwt_token = auth.exchange_token_with_audience(iam_base_url,
                                                  iam_client_id, iam_client_secret, access_token, vault_bound_audience)

        vault_client = vaultservice.connect(jwt_token, vault_role)
        path = "services_credential/" + serviceid
        secret = vault_client.write_service_creds(path, creds)

        flash("Credentials successfully written!", 'info')

        return redirect(url_for('vault_bp.manage_service_creds'))


@vault_bp.route('/delete_credentials')
@auth.authorized_with_valid_token
def delete_service_creds():
    vault_bound_audience = app.config.get('VAULT_BOUND_AUDIENCE')
    vault_role = app.config.get("VAULT_ROLE")

    serviceid = request.args.get('service_id', "")

    access_token = app.get_auth_blueprint().session.token['access_token']

    jwt_token = auth.exchange_token_with_audience(iam_base_url,
                                                  iam_client_id, iam_client_secret, access_token, vault_bound_audience)

    vault_client = vaultservice.connect(jwt_token, vault_role)
    path = "services_credential/" + serviceid
    vault_client.delete_service_creds(path)

    flash("Credentials successfully deleted!", 'info')

    return redirect(url_for('vault_bp.manage_service_creds'))
